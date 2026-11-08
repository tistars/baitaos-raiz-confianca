#!/usr/bin/env node
// Verificador de bootstrap do pacote da versão (card 03-s1). Arquivo único: só node e cosign, sem importar nada do pacote
// recebido e sem executar nada que venha nele. É o PRIMEIRO passo da conferência: antes de qualquer sha256sum -c ou
// cosign verify-blob com a chave que viaja na pasta (quem troca pacote e chave juntos passaria por esses).
//
//   node verificar-raiz.mjs --pacote <pasta da versão> --raiz raiz-confianca.json [--data AAAA-MM-DD]
//
// Obtenha este arquivo e a raiz-confianca.json por canal independente do pacote (o da cópia dentro da pasta só vale se o
// sha256 dela bater com o que a Stars informou por fora). Sai 0 e imprime a impressão da chave e a versão; sai 1 recusando
// (motivo no stderr); sai 2 em uso errado ou sem cosign.
//
// raiz-confianca.json
//   { "versao": 1,
//     "chaves": [ { "impressao": "<sha256 hex do SPKI DER>", "chavePublica": "<PEM>" },                     a primeira é a âncora
//                 { "impressao": ..., "chavePublica": ..., "assinaturaDaAnterior": "<base64>" } ],         as seguintes: rotação
//     "revogadas": [ { "impressao": "<sha256 hex>", "revogadaEm": "AAAA-MM-DD" } ] }
// A rotação é a assinatura (cosign sign-blob) da chave ANTERIOR da lista sobre o texto
//   "stars-enterprise raiz-de-confianca v1\nanterior:<impressão anterior>\nnova:<impressão nova>\n"
// Chave revogada recusa o pacote cuja data (a do NOTAS.md, coberta pelo SHA256SUMS assinado, ou --data, o que for maior)
// é igual ou posterior à data de revogação.
import crypto from 'node:crypto'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { spawnSync } from 'node:child_process'

const ASSINATURA = 'SHA256SUMS.cosign.sig'
const HEX64 = /^[0-9a-f]{64}$/

class Recusa extends Error {}
const recusar = (m) => {
  throw new Recusa(m)
}

const dataValida = (s) => typeof s === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(s) && new Date(`${s}T00:00:00Z`).toISOString().slice(0, 10) === s

const impressaoDe = (pem) => crypto.createHash('sha256').update(crypto.createPublicKey(pem).export({ type: 'spki', format: 'der' })).digest('hex')

function hashDoArquivo(arq) {
  const h = crypto.createHash('sha256')
  const fd = fs.openSync(arq, 'r')
  try {
    const buf = Buffer.alloc(1 << 20)
    for (let n = fs.readSync(fd, buf, 0, buf.length, null); n > 0; n = fs.readSync(fd, buf, 0, buf.length, null)) h.update(buf.subarray(0, n))
  } finally {
    fs.closeSync(fd)
  }
  return h.digest('hex')
}

/** o cosign do PATH do operador, nunca um de dentro do pacote nem de entrada relativa do PATH (".", vazia) */
function acharCosign(pacote) {
  const real = fs.realpathSync(pacote)
  for (const d of (process.env.PATH ?? '').split(path.delimiter)) {
    if (!d || !path.isAbsolute(d)) continue
    const arq = path.join(d, 'cosign')
    let alvo
    try {
      alvo = fs.realpathSync(arq)
      fs.accessSync(alvo, fs.constants.X_OK)
    } catch {
      continue
    }
    if (alvo === real || alvo.startsWith(real + path.sep)) continue
    return alvo
  }
  return null
}

function verificarBlob(cosign, chavePem, assinaturaB64, conteudo) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'verificar-raiz-'))
  try {
    fs.writeFileSync(path.join(tmp, 'chave.pub'), chavePem)
    fs.writeFileSync(path.join(tmp, 'blob'), conteudo)
    fs.writeFileSync(path.join(tmp, 'blob.sig'), assinaturaB64)
    const r = spawnSync(cosign, ['verify-blob', '--key', 'chave.pub', '--signature', 'blob.sig', '--insecure-ignore-tlog=true', 'blob'], { cwd: tmp, encoding: 'utf8', stdio: ['ignore', 'ignore', 'ignore'] })
    return r.status === 0
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true })
  }
}

const mensagemRotacao = (anterior, nova) => `stars-enterprise raiz-de-confianca v1\nanterior:${anterior}\nnova:${nova}\n`

/** lê a raiz e confere a cadeia de rotação; devolve { chaves: Map(impressão → PEM), revogadas: Map(impressão → data) } */
function lerRaiz(arq, cosign) {
  let bruto
  let j
  try {
    bruto = fs.readFileSync(arq)
    j = JSON.parse(bruto.toString('utf8'))
  } catch (e) {
    recusar(`raiz de confiança ilegível (${arq}): ${e.message}`)
  }
  if (j?.versao !== 1 || !Array.isArray(j.chaves) || !j.chaves.length) recusar('raiz de confiança inválida: falta versao 1 e a lista "chaves"')
  const chaves = new Map()
  let anterior = null
  j.chaves.forEach((c, i) => {
    let impressao
    try {
      impressao = impressaoDe(c?.chavePublica)
    } catch {
      recusar(`raiz de confiança: a chavePublica da entrada ${i + 1} não é uma chave pública PEM`)
    }
    if (c.impressao !== impressao) recusar(`raiz de confiança: a impressão da entrada ${i + 1} (${c.impressao}) não é a da chavePublica dela (${impressao})`)
    if (chaves.has(impressao)) recusar(`raiz de confiança: chave repetida (${impressao})`)
    if (i === 0) {
      if (c.assinaturaDaAnterior !== undefined) recusar('raiz de confiança: a primeira chave é a âncora e não tem anterior que a assine')
    } else {
      if (typeof c.assinaturaDaAnterior !== 'string' || !c.assinaturaDaAnterior) recusar(`chave ${impressao} sem assinatura da anterior: chave nova só vale se a anterior a assinou`)
      if (!verificarBlob(cosign, anterior.pem, c.assinaturaDaAnterior, mensagemRotacao(anterior.impressao, impressao))) recusar(`chave ${impressao}: a assinatura da anterior não confere (${anterior.impressao})`)
    }
    chaves.set(impressao, c.chavePublica)
    anterior = { impressao, pem: c.chavePublica }
  })
  const revogadas = new Map()
  for (const r of j.revogadas ?? []) {
    if (!HEX64.test(r?.impressao ?? '') || !dataValida(r.revogadaEm)) recusar('raiz de confiança: revogadas é [{ impressao (sha256 hex), revogadaEm (AAAA-MM-DD) }]')
    if (!revogadas.has(r.impressao) || r.revogadaEm < revogadas.get(r.impressao)) revogadas.set(r.impressao, r.revogadaEm)
  }
  return { chaves, revogadas, sha: crypto.createHash('sha256').update(bruto).digest('hex') }
}

/** arquivos da pasta (caminhos com /), sem seguir link simbólico: link ou arquivo especial recusa */
function listar(pasta, base = '') {
  return fs.readdirSync(path.join(pasta, base), { withFileTypes: true }).flatMap((d) => {
    const rel = path.posix.join(base, d.name)
    if (d.isSymbolicLink()) recusar(`link simbólico no pacote: ${rel}`)
    if (d.isDirectory()) return listar(pasta, rel)
    if (!d.isFile()) recusar(`arquivo especial no pacote: ${rel}`)
    return [rel]
  })
}

function lerSomas(texto) {
  const somas = new Map()
  for (const linha of texto.split('\n')) {
    if (!linha) continue
    const m = /^([0-9a-f]{64}) {2}(.+)$/.exec(linha)
    if (!m) recusar(`SHA256SUMS: linha fora do formato: ${linha.slice(0, 80)}`)
    const [, hash, rel] = m
    if (rel.startsWith('/') || rel.includes('\\') || rel.split('/').some((p) => p === '..' || p === '.' || p === '')) recusar(`SHA256SUMS: caminho inválido: ${rel}`)
    if (somas.has(rel)) recusar(`SHA256SUMS: caminho repetido: ${rel}`)
    somas.set(rel, hash)
  }
  if (!somas.size) recusar('SHA256SUMS vazio')
  return somas
}

export function verificarRaiz({ pacote, raiz, data }) {
  if (data !== undefined && !dataValida(data)) throw new Recusa('--data tem de ser AAAA-MM-DD')
  if (!fs.existsSync(pacote) || !fs.statSync(pacote).isDirectory()) recusar(`pacote não encontrado: ${pacote}`)
  const cosign = acharCosign(pacote)
  if (!cosign) {
    const e = new Error('cosign não encontrado no PATH (https://github.com/sigstore/cosign/releases)')
    e.uso = true
    throw e
  }
  const r = lerRaiz(raiz, cosign)
  const lerDoPacote = (rel) => {
    const arq = path.join(pacote, rel)
    if (!fs.existsSync(arq) || fs.lstatSync(arq).isSymbolicLink() || !fs.statSync(arq).isFile()) recusar(`pacote recusado: ${rel} ausente`)
    return fs.readFileSync(arq)
  }

  // 1. a chave que o pacote traz tem de ser uma das da raiz: é o que a troca de pacote+chave+assinatura na mesma pasta não consegue
  const trazida = lerDoPacote('chave-cosign.pub')
  let impressao
  try {
    impressao = impressaoDe(trazida)
  } catch {
    recusar('pacote recusado: chave-cosign.pub não é uma chave pública PEM')
  }
  if (!r.chaves.has(impressao)) recusar(`chave fora da raiz de confiança: a chave-cosign.pub do pacote tem impressão sha256 ${impressao}, que não está entre as ${r.chaves.size} da raiz`)

  // 2. a assinatura do SHA256SUMS confere com a chave DA RAIZ
  const somasBruto = lerDoPacote('SHA256SUMS')
  if (!verificarBlob(cosign, r.chaves.get(impressao), lerDoPacote(ASSINATURA).toString('utf8').trim(), somasBruto)) recusar(`pacote recusado: a assinatura Cosign do SHA256SUMS não confere com a chave ${impressao} da raiz`)

  // 3. nada além do que foi assinado: cada arquivo com o hash da lista e nenhum a mais
  const somas = lerSomas(somasBruto.toString('utf8'))
  const presentes = listar(pacote).filter((f) => f !== 'SHA256SUMS' && f !== ASSINATURA)
  for (const f of presentes) if (!somas.has(f)) recusar(`pacote recusado: arquivo fora do SHA256SUMS: ${f}`)
  for (const [f, h] of somas) {
    if (!presentes.includes(f)) recusar(`pacote recusado: ${f} está no SHA256SUMS e não na pasta`)
    if (hashDoArquivo(path.join(pacote, f)) !== h) recusar(`pacote recusado: ${f} é diferente do assinado`)
  }

  // 4. versão e data do que foi assinado; revogação por data
  const versaoDoIndice = /^# versao (\S+)$/m.exec(lerDoPacote('IMAGENS.txt').toString('utf8'))?.[1]
  const cabecalho = /^# Stars Enterprise · versão (\S+) \((\d{4}-\d{2}-\d{2})\)$/m.exec(lerDoPacote('NOTAS.md').toString('utf8'))
  if (!versaoDoIndice || !cabecalho || cabecalho[1] !== versaoDoIndice || !dataValida(cabecalho[2])) recusar('pacote recusado: versão e data não legíveis em IMAGENS.txt e NOTAS.md (ou divergentes)')
  const dataPacote = data && data > cabecalho[2] ? data : cabecalho[2]
  const revogada = r.revogadas.get(impressao)
  if (revogada && dataPacote >= revogada) recusar(`chave ${impressao} revogada em ${revogada}: o pacote é de ${dataPacote}, assinado depois da revogação`)
  return { impressao, versao: versaoDoIndice, data: cabecalho[2], arquivos: somas.size, chaves: r.chaves.size, revogadas: r.revogadas.size, raizSha: r.sha }
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fs.realpathSync(new URL(import.meta.url).pathname)) {
  const USO = 'uso: node verificar-raiz.mjs --pacote <pasta da versão> --raiz raiz-confianca.json [--data AAAA-MM-DD]'
  const o = {}
  const argv = process.argv.slice(2)
  for (let i = 0; i < argv.length; i += 2) {
    if (!['--pacote', '--raiz', '--data'].includes(argv[i]) || argv[i + 1] === undefined) {
      console.error(USO)
      process.exit(2)
    }
    o[argv[i].slice(2)] = argv[i + 1]
  }
  if (!o.pacote || !o.raiz) {
    console.error(USO)
    process.exit(2)
  }
  try {
    const v = verificarRaiz({ pacote: path.resolve(o.pacote), raiz: path.resolve(o.raiz), data: o.data })
    console.log(`raiz de confiança: sha256 ${v.raizSha} (${v.chaves} chaves, ${v.revogadas} revogadas)`)
    console.log(`chave de release: sha256 ${v.impressao}`)
    console.log(`pacote conferido: versão ${v.versao} (${v.data}), assinatura Cosign do SHA256SUMS e ${v.arquivos} arquivos`)
  } catch (e) {
    console.error(`verificar-raiz: ${e instanceof Recusa || e.uso ? e.message : `erro inesperado: ${e.message}`}`)
    process.exit(e.uso ? 2 : 1)
  }
}
