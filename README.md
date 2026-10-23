# Regras ModSecurity

Coleção de regras defensivas de **ModSecurity**, cada uma autossuficiente na sua pasta, para **Apache (ModSecurity v2)** e **Nginx + libModSecurity v3**.

> **Aviso geral:** regras de WAF são **defesa em profundidade**, não correção. Elas não substituem atualizar o software vulnerável e não provam que um sistema está seguro. Teste em homologação (`SecRuleEngine DetectionOnly`) e acompanhe os logs antes de ativar o bloqueio em produção.

## Regras disponíveis

| Regra | Alvo | Faixa de IDs | Status |
| --- | --- | --- | --- |
| [`php2shell`](rules/php2shell/) | CVE-2026-109619 e CVE-2026-115560 (PHP `session.upload_progress`) | `1005001`–`1005005` | Testada em Apache v2 e Nginx v3 |

> As falhas no progresso de upload do PHP envolvem três CVEs. Esta regra cobre o mesmo ponto de entrada (campo `PHP_SESSION_UPLOAD_PROGRESS`) de **duas**: **CVE-2026-109619** e **CVE-2026-115560**. A **CVE-2026-109618** (corrupção de memória por *out-of-memory*) **não é coberta por nenhuma regra de WAF**. Em todos os casos, a proteção real é atualizar o PHP e/ou desligar o progresso de upload, detalhes no [README da regra](rules/php2shell/).

> Cada regra tem seu próprio `README.md` com instalação, teste e limitações.

## Estrutura

```
rules/
└── <nome-da-regra>/
    ├── README.md               doc da regra (instalação, teste, limitações)
    ├── modsecurity-<nome>.conf  a(s) regra(s)
    ├── examples/               trechos de integração Apache/Nginx
    └── tests/                  teste HTTP inofensivo (curl)
```

## Como usar

1. Escolha a regra em `rules/<nome>/` e leia o `README.md` dela
2. Ajuste os **IDs** para uma faixa livre no seu ambiente (veja a convenção abaixo)
3. Inclua o `.conf` na configuração do ModSecurity (`Include`/`IncludeOptional`)
4. Valide em `DetectionOnly`, depois ative o bloqueio

## Convenção de IDs

Para evitar colisão entre regras deste repositório, cada regra reserva uma faixa de 100 IDs a partir de `1005000`:

| Faixa | Regra |
| --- | --- |
| `1005000`–`1005099` | php2shell |
| `1005100`–`1005199` | (livre) |

Confirme sempre que a faixa está livre **no seu ambiente** antes de aplicar.

## Licença

MIT, veja `LICENSE`.
