# Raiz de confiança das releases BaitaOS Enterprise

Canal independente do pacote de instalação. Contém:

- `verificar-raiz.mjs` — verificador de bootstrap (só `node` e `cosign`).
- `raiz-confianca.json` — chaves públicas de release aceitas (publicada após a cerimônia de chave).

Como conferir uma release:

1. Baixe estes dois arquivos **daqui**, nunca de dentro do pacote.
2. Confira a impressão da chave (SHA-256 do SPKI) com a que a Stars informou por outro meio (WhatsApp).
3. `node verificar-raiz.mjs --pacote <pasta-da-versao> --raiz raiz-confianca.json` — sai 0 se a assinatura bate com a raiz; sai 1 recusando.

Este repositório não contém chaves privadas. Revogação e rotação entram em `raiz-confianca.json` (campo `revogadas` / chaves seguintes).
