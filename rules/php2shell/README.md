# php2shell — mitigação ModSecurity (CVE-2026-109619)

Regra defensiva de **ModSecurity** para bloquear requisições com o parâmetro `PHP_SESSION_UPLOAD_PROGRESS`, empregado em uma técnica pública relacionada a **CVE-2026-109618** e **CVE-2026-109619** para **Apache** e **Nginx + libModSecurity v3**.

> **Atenção:** a regra não corrige o PHP, não detecta todas as formas de exploração, e não é prova de que um site esteja seguro. A medida essencial é atualizar o PHP para uma versão corrigida (ou pacote equivalente com correção). Pode haver falsos positivos em aplicações que realmente utilizam o campo de progresso de upload.

## O que esta regra NÃO cobre

Há **duas** CVEs. Esta regra atua **somente** no vetor de progresso de upload, que é o da **CVE-2026-109619**.

A **CVE-2026-109618** (corrupção de memória no tratamento de *out-of-memory*) **não é coberta por nenhuma regra de WAF** - não depende do campo `PHP_SESSION_UPLOAD_PROGRESS` nem de assinatura observável no corpo. Isso está confirmado também pelos fornecedores de regras comerciais. **Não confie no WAF para a CVE-2026-109618.**

##  Correção e mitigação rápidas (até atualizar o PHP)

O WAF é **defesa em profundidade**, não a correção. Em ordem de prioridade:

**1. Atualize o PHP** (correção real das duas CVEs). Versões corrigidas (21/10/2026):
**8.2.35**, **8.3.36**, **8.4.27** ou **8.5.12**. Para 8.1 e anteriores, use o backport do seu fornecedor (distribuição/cPanel/EasyApache).

**2. Enquanto não atualiza - mitigação oficial da CVE-2026-109619.** Desligue o progresso de upload no `php.ini` ou no pool do PHP-FPM (não via `ini_set()` nem `.user.ini`) e reinicie os workers:

```ini
; php.ini ou pool do PHP-FPM (ex.: /etc/php/8.3/fpm/pool.d/www.conf -> php_admin_value)
session.upload_progress.enabled = 0
```

```ini
; PHP-FPM pool (sintaxe de pool)
php_admin_value[session.upload_progress.enabled] = 0
```

```apache
# Apache mod_php (dentro do VirtualHost/Directory)
php_admin_flag session.upload_progress.enabled Off
```

Depois reinicie: `systemctl restart php*-fpm` (FPM) ou `systemctl reload apache2`/`httpd` (mod_php). Confirme com `php -i | grep upload_progress` ou numa página `phpinfo()`.

**3. Reduza a exposição da CVE-2026-109618 (OOM).** Não há WAF que cubra; siga o aviso oficial:

```ini
post_max_size = 8M        ; ou ~32M se há uploads; evite valores altos
; memory_limit: siga a recomendação do aviso oficial para seu cenário
```

Além disso, use limites de cgroup/container como barreira de disponibilidade e, no PHP 8.5, considere `fatal_error_backtraces = 0`.

## Conteúdo desta pasta

- `modsecurity-php2shell.conf` - regra compartilhada entre Apache e Nginx, com IDs editáveis
- `examples/apache.conf.example` - notas de integração Apache/cPanel
- `examples/nginx.conf.example` - notas de integração Nginx
- `tests/teste-http.sh` - teste HTTP inofensivo, requer `curl`

## Vulnerabilidades

- **CVE-2026-109618:** no tratamento de falta de memória (*out-of-memory/OOM*), a requisição pode ficar com dados internos parcialmente inicializados e a rotina de limpeza pode tratar esses dados inválidos como válidos, podendo resultar em corrupção de memória e execução remota de código. **(Esta regra não cobre.)**
- **CVE-2026-109619:** estado interno de uma requisição pode continuar apontando para memória já liberada; uma requisição posterior processada pelo mesmo worker pode acessar esse estado antigo, com risco de execução remota de código. **(Alvo desta regra, pelo caminho de progresso de upload.)**

A regra aqui publicada **não corrige esses erros internos do PHP**. Atua apenas em uma possível entrada do ataque observada em demonstrações públicas.

## Como a regra funciona

O arquivo `modsecurity-php2shell.conf` tem várias regras. A principal:

```apache
SecRequestBodyAccess On
SecRequestBodyLimitAction Reject
SecRule ARGS_NAMES "@streq PHP_SESSION_UPLOAD_PROGRESS" \
    "id:1005001,phase:2,t:none,deny,status:403,log,\
    msg:'PHP2Shell: parametro PHP_SESSION_UPLOAD_PROGRESS bloqueado',\
    severity:'CRITICAL',\
    tag:'PHP2Shell',tag:'CVE-2026-109619'"
```

As demais regras fecham formas de contornar a assinatura simples:

| ID | O que faz | Por quê |
| --- | --- | --- |
| `1005001` | Bloqueia o nome exato do campo em `ARGS_NAMES` | Vetor direto do exploit público |
| `1005002` | Bloqueia quando `REQBODY_ERROR != 0` | Se o WAF não consegue processar o corpo, `ARGS_NAMES` fica vazio e a assinatura passaria batido, mas o PHP ainda pode ler o corpo |
| `1005003` | Bloqueia `MULTIPART_STRICT_ERROR != 0` | Multipart ambíguo/malformado onde WAF e PHP divergem |
| `1005004` | Bloqueia `Content-Type: multipart` que não passou pelo parser multipart do WAF | Fecha o caso em que o corpo não é inspecionado |
| `1005005` | Reexamina os cabeçalhos crus de cada parte procurando o nome do campo | Segunda camada; requer ModSecurity 2.9.6+ ou libModSecurity 3.0.8+ |

`SecRequestBodyLimitAction Reject` é importante: com `ProcessPartial` (padrão em
muitas instalações), o conteúdo além do limite do corpo não é inspecionado e o
campo poderia ser escondido depois de um preenchimento grande (*padding*).

| Campo | Explicação |
| --- | --- |
| `SecRequestBodyAccess On` | Habilita inspeção do corpo HTTP, pode já estar ligado na configuração global |
| `SecRule` | Define uma regra do motor ModSecurity |
| `ARGS_NAMES` | Verifica os **nomes** dos parâmetros reconhecidos pelo parser HTTP |
| `@streq PHP_SESSION_UPLOAD_PROGRESS` | Compara exatamente com o nome do parâmetro |
| `id:1005001` | Número único no ambiente; **personalize conforme sua faixa livre** |
| `phase:2` | Executa após processamento do corpo da requisição, se disponível |
| `t:none` | Não aplica transformações adicionais (como o PHP, a comparação do campo é sensível a maiúsculas) |
| `deny` | Bloqueia quando o motor está em modo ativo |
| `status:403` | Responde HTTP 403 Forbidden |
| `log` | Registra o evento de correspondência |
| `msg` | Mensagem apresentada no evento |
| `severity` | Categoria de severidade para organização de logs |
| `tag` | Marcadores pesquisáveis, não mudam a lógica da detecção |

**Observação técnica:** o parâmetro é o nome padrão de `session.upload_progress.name`. Se esse nome foi alterado no PHP, adapte a regra. O ModSecurity e o PHP podem interpretar `multipart/form-data` de maneira diferente, então essa assinatura não oferece cobertura completa.

## Instalação — Apache / WHM-cPanel

1. Verifique se o ModSecurity está instalado/ativo e se `SecRuleEngine On` está efetivo.
2. No **WHM -> Security Center -> ModSecurity Tools -> Rules List -> Add Rule**, insira a regra presente em `modsecurity-php2shell.conf` e confirme que os IDs escolhidos estão livres. Se `SecRequestBodyAccess On` já for definido globalmente, mantenha lá e não o repita no editor que aceite apenas `SecRule`.
3. Em Apache gerenciado diretamente, inclua o arquivo de regras na configuração já utilizada pelo ModSecurity (`Include` ou `IncludeOptional`). Não edite arquivos gerados automaticamente pelo cPanel.
4. Valide a configuração e recarregue o serviço pelo mecanismo adequado ao seu ambiente.

## Instalação — Nginx + ModSecurity v3

**Pré-requisito:** o Nginx precisa ter o **conector ModSecurity v3** instalado e carregado. Nginx puro não interpreta `SecRule`.

1. Copie `modsecurity-php2shell.conf` para, por exemplo, `/etc/nginx/modsec/modsecurity-php2shell.conf`.
2. No arquivo de configuração principal carregado pelo ModSecurity (`/etc/nginx/modsec/main.conf`, ou equivalente), adicione:
   ```apache
   Include /etc/nginx/modsec/modsecurity-php2shell.conf
   ```
3. No contexto `http`, `server` ou `location` pertinente do Nginx, configure (ajustando o caminho):
   ```nginx
   modsecurity on;
   modsecurity_rules_file /etc/nginx/modsec/main.conf;
   ```
4. Certifique-se de que `SecRuleEngine On` e as configurações base necessárias estejam ativas.
5. Execute `nginx -t` e, se aprovado, `systemctl reload nginx`.

**Dica:** ao usar Nginx como proxy para Apache, confira **em qual camada** o ModSecurity está rodando para não assumir proteção inexistente.

## Teste controlado

Em um domínio que você administra ou está autorizado a testar:

```bash
bash tests/teste-http.sh https://seudominio.example/
```

O script envia requisições POST **inofensivas** (apenas o nome do campo com valor tosco, não testa RCE nem envia payload malicioso) em três casos:

1. campo `PHP_SESSION_UPLOAD_PROGRESS` simples -> espera-se `403`;
2. o mesmo campo escondido após 200 KB de preenchimento -> espera-se `403` ou `413`;
3. multipart malformado (sem *boundary*) -> espera-se `400`.

**Confirme o ID escolhido no log do ModSecurity**, pois um `403` isolado pode vir de outro mecanismo. Qualquer resultado aqui também não prova (nem afasta) vulnerabilidade.

## Validação feita neste repositório

As regras foram testadas em contêineres com as duas pilhas: **Apache + ModSecurity v2** e **Nginx + libModSecurity v3** (imagens `owasp/modsecurity-crs`, CRS desligado para isolar só estas regras), com um backend PHP 8.3 real. Observado:

- campo em multipart válido: bloqueado (403) nas duas pilhas, e confirmado que esse é o caso que faz o PHP registrar o progresso de upload;
- campo após 200 KB de *padding*: bloqueado (413 no Apache, 403 no Nginx);
- multipart sem *boundary*: bloqueado (400) nas duas;
- nome em minúsculas e corpo não-multipart: o PHP **não** registra o campo (vetor não é acionado);
- uploads legítimos, formulários simples e JSON: **não** bloqueados (sem falso positivo nos testes).

## Limitações e operações

- Atualizar PHP é indispensável: WAF é **defesa em profundidade**.
- A regra cobre o caminho de progresso de upload (CVE-2026-109619), **não** o caminho de falta de memória da CVE-2026-109618.
- `SecRuleEngine DetectionOnly` apenas registra, sem aplicar `deny` - use-o para validar antes de ativar o bloqueio.
- A detecção depende da configuração e do parser de corpo da requisição do ModSecurity.
- Pode causar falsos positivos com clientes que utilizem o progresso de upload da sessão PHP, e a regra 1005003 pode ser sensível a multipart gerado por clientes antigos.
- A regra não identifica nem mitiga todos os vetores das duas CVEs.
- Teste em homologação e acompanhe os logs antes da distribuição global.

## Referências

- PHP Security Advisory (21/10/2026): https://www.php.net/archive/2026.php
- cPanel / EasyApache: https://support.cpanel.net/hc/en-us/articles/44397389677335-Critical-PHP-Security-Release-CVE-2026-109618-and-CVE-2026-109619
- Nginx + libModSecurity v3: https://modsecurity.org/docs/2-installation/2-2-libmodsecurity-v3-nginx/
- UK NCSC: https://www.ncsc.gov.uk/news/critical-security-issue-affecting-php
