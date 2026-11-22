# Auditoria retrospectiva — o que passou despercebido e o que foi verificado agora

**Data:** 2026-11-22 · Todas as verificações abaixo foram executadas agora, somente leitura.

## Despercebidos que eram FATOS NÃO REPORTADOS (agora verificados)

| # | Item | Verificação executada agora | Resultado |
|---|---|---|---|
| 1 | **`Summary.json` no user data do XVC (204 B) — nunca aberto por nenhuma fase** | dump direto | **`GDKVersion: "10.0.26100.7822"`** + flags: IntelligentDelivery=false, InstallFeatures/Recipes=false, **SupportsDefaultEnableMods=true**. É a primeira evidência direta da **versão do GDK** usada no empacotamento — metadado de pipeline que faltava ao relatório de identidade. `Metadata.json` = `{}` vazio. |
| 2 | **Proveniência do `gameos.xvd` nunca vinculada ao XVC** | comparação byte a byte da região `XVC-EXVD` embutida × arquivo em disco | **RESOLVIDO: idênticos** — mesmo tamanho (0x14BF2000), mesmo VDUID/build, **332/332 blocos de 1 MiB iguais, zero divergência**. O gameos.xvd em disco é a **extração do volume EraOS embutido no próprio XVC** (região 0x3000..0x14BF5000). Analisáramos o volume em isolamento; o vínculo com o pacote estava despercebido. |
| 3 | **Página XVC-MDU (dado mutável, 1 página) nunca examinada** | dump | 31 bytes não-zero, todos `0x03`, resto zeros — conteúdo trivial de dados mutáveis, agora documentado. |
| 4 | **Configs em disco × configs DENTRO do XVC nunca diferenciados** | diff byte a byte (3 arquivos) | **Idênticos** (MicrosoftGame.Config, appxmanifest.xml, microsoft_gameconfig.bin) — as cópias em disco são fiéis às embutidas; a preocupação com "edições pós-fábrica" não se aplica ao estado atual. |
| 5 | **Página 0 do `Catalog000.bin` (64 B) nunca decodificada** | dump + 3 hipóteses de hash | 64 bytes aparentemente aleatórios; **não** são SHA-256 da seção, do catálogo inteiro nem dos bytes gravados do exe → função **UNKNOWN** (hipóteses refutadas e documentadas). |
| 6 | **Estado de assinatura das 16 DLLs nunca verificado** | parse do security directory | **Nenhuma** das 16 tem security dir embutido (sem Authenticode in-file) — coerente com empacotamento console: integridade de código fica na hash tree + catálogo do pacote, não por arquivo. |

## Despercebido conceitual (parcialmente caracterizado agora)

**A proveniência das DLLs plaintext.** A pasta do jogo é **híbrida**: DLLs legíveis + exe cifrado — logo **não** é extração pura do XVC (tudo viria cifrado) nem instalação de console pura (tudo viria decifrado). Verificações novas: as CRT **não** são as cópias públicas do Windows desktop (hashes distintos — builds console/onecore-xbox) e nenhuma DLL carrega assinatura embutida. Conclusão reforçada: o material plaintext veio de um **ambiente console/devkit**, montado a partir de ≥2 fontes — a origem exata permanece **UNKNOWN** e é a única lacuna de proveniência do conjunto em disco.

## Já estava coberto (nada de novo, confirmado)

Cauda de 3.072 B (page slack, provada), `data_unit` (auditoria integral 29.342 folhas), hash dos bytes gravados, KeyMaterial zero do XVC × não-zero do gameos, diferenciação StandardOdk × chave regional — tudo já documentado nas fases anteriores.

## Itens abertos que permanecem UNKNOWN (sem palpite)

1. Função dos 64 B da página 0 do catálogo;
2. Hash compartilhado XVC-HD/XVC-MD (serialização desconhecida; hipóteses anteriores refutadas);
3. Origem exata das cópias plaintext das DLLs console;
4. `PECatalogHash` (gameos e título): serializações candidatas refutadas.

## Consequência prática

O item 1 (GDK 10.0.26100.7822) deve entrar como evidência de pipeline no `identity_report`; o item 2 fecha a proveniência do gameos.xvd (não é um artefato órfão — é parte do XVC); nada disso altera o bloqueio central (CIK ausente; nenhum artefato autorizado da build existe no ambiente).
