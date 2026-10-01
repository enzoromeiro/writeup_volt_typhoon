# 🧾 Write-up - Volt Typhoon 
### Este projeto foca em como investigar a sala Volt Typhoon da plataforma TryHackMe, utilizando consultas Splunk SPL, MITRE ATT&CK e pensamento analítico. 

![introdução](img/introducao.jpeg)

### 🌪 Quem é Volt Typhoon? 

Segundo o MITRE ATT&CK, Volt Typhoon (G1017), é um ator patrocinado pelo Estado da República Popular da China (RPC) que está ativo desde pelo menos 2021, visando principalmente organizações de infraestrutura crítica nos EUA e seus territórios, incluindo Guam. O direcionamento e o padrão de comportamento do Volt Typhoon foram avaliados como pré-posicionamento para permitir o movimento lateral para ativos de tecnologia operacional (OT) para possíveis ataques destrutivos ou disruptivos. O Volt Typhoon enfatizou a furtividade nas operações usando web shells, binários living-off-the-land (LOTL), atividades práticas de teclado e credenciais roubadas.

#### O que é a técnica Living Off The Land?

É uma técnica de evasão de defesa, onde o atacante, após comprometer um sistema, utiliza binários e ferramentas legítimas do próprio sistema operacional para executar ações maliciosas, dificultando a detecção por antivírus e EDRs que confiam nessas ferramentas.

#### ⚙ Para a execução desse Write-up, foram utilizados apenas a sala Volt Typhoon da plataforma TryHackMe e o Splunk, que também é disponibilizado por eles na plataforma. Nesta sala, é preciso saber Splunk SPL (linguagem de consulta do Splunk) para podermos achar eventos suspeitos e então analisar os logs. Também é necessário utilizar o framework MITRE ATT&CK, para estudarmos o grupo e suas táticas, técnicas e procedimentos.

### 1. Scenario:

![Cenário](img/1.jpeg)

### 2. Initial Access

![Acesso inicial](img/2.jpeg)

Active Directory Self Service é um serviço de autoatendimento para usuários de um domínio, usado para gerenciamento de senhas. Para esta primeira questão, vamos analisar os logs desse serviço, então o sourcetype na consulta será "adss". Como é dito na questão, o grupo Volt Typhoon geralmente obtém acesso inicial na rede explorando vulnerabilidades em software empresarial, e recentemente foi visto explorando o ADSelfService, a outra pista é que estamos procurando em qual momento a senha do usuário **dean** foi alterada e assumida pelo invasor.

Com essas informações em mãos, iremos fazer a seguinte consulta SPL: 
`index=* sourcetype="adss" username="*dean*" action_name="Password Change" | table timestamp username action_name status`

Obviamente, precisa ser feito um estudo prévio e uma análise do tipo de log que estamos lidando, para saber o que consultar.
Explicando rapidamente a consulta: estamos procurando o usuário **dean**, executando uma ação de troca de senha e organizando a saída em uma tabela com as colunas de tempo, usuário, nome da ação e o resultado da ação.

(`"*"` considera qualquer caractere que tenha no espaço onde se encontra, ou seja, busca o usuário **dean** mesmo se houver algum nome antes ou depois. 
`EX: admin-dean, dean-admin, user-dean-admin`) 

![Acesso inicial](img/2-a.jpeg)

Podemos ver que a resposta da consulta mostrou dois eventos com datas diferentes e com o mesmo usuário `dean-admin` (informação relevante na sala, nome completo do usuário comprometido). Entretanto, apenas um evento consta como status completed, e a data desse evento é a resposta `2024-03-24T11:10:22`. 

A outra questão quer o nome da nova conta de administrador, criada pouco tempo após o comprometimento do usuário dean-admin. 

A consulta: `index=* sourcetype="adss" action_name="Enrollment" | table timestamp username action_name status`

Explicando a consulta: Estamos procurando uma ação de `Enrollment` (registro de novos usuários no adss) e organizando a saída em uma tabela com as colunas de tempo, usuário, nome da ação e o resultado da ação.

![Acesso inicial](img/2-b.jpeg)

A resposta da consulta mostrou esse evento com o usuário `voltyp-admin`, o usuário administrador que foi criado e adicionado ao Active Directory Self Service.

### 3. Execution

![Execução](img/3.jpeg)

WMIC, de forma simplificada, é como se fosse o painél de controle do Windows mas via linha de comando. É uma ferramenta nativa do Windows mas que foi descontinuada e só foi removida permanentemente no Windows 11, seu substituto passa a ser o PowerShell. 
A questão diz que o grupo Volt Typhoon aproveitam o wmic ativo no sistema para realizar tarefas como coletar informações e despejar bancos de dados valiosos. A primeira pergunta quer saber o comando que o invasor executou para encontrar informações sobre unidades locais no `server01` e `server02`, vamos usar o nome desses servidores na consulta. 

![Execução](img/3-a.jpeg)

Vou fazer a seguinte consulta: `index="main" sourcetype="wmic" username="*dean-admin*" ("*server01*" OR "*server02*") | table _time host username command result`

Explicando a consulta: Estamos procurando nos logs do wmic algum evento que venha do usuário dean-admin (a conta comprometida), que contenha a palavra "server01" ou "server02" em algum lugar dele, e organizando a saída em uma tabela com as colunas de tempo, host(máquina), usuário, comando digitado e o resultado.

![Execução](img/3-b.jpeg)

A resposta da consulta mostrou esse evento vindo da máquina volthunter e o comando digitado pelo atacante para coletar informações sobre unidade de disco local `wmic /node:server01, server02 logicaldisk get caption, filesystem, freespace, size, volumename`, resultado = sucesso.

A segunda pergunta quer saber qual senha o invasor define no arquivo, e o contexto é que o invasor usa o ntdsutil para criar uma cópia do banco de dados do AD, move essa cópia para um servidor web e compacta o banco de dados.

Vou fazer a seguinte consulta: `index="main" sourcetype="wmic" username="*dean-admin*" "*ntdsutil*"`

Explicando a consulta: Estamos procurando nos logs do wmic algum evento que venha do usuário dean-admin (a conta comprometida), que contenha a palavra "ntdsutil" nele.

A resposta da consulta mostrou um evento vindo do usuário dean-admin e da máquina server02 com o comando `wmic process call create "cmd.exe /c mkdir C:\Windows\Temp\tmp & ntdsutil.exe \"ac i ntds\"\"ifm create full C:\Windows\Temp\tmp\temp.dit""`, nesse comando ele cria o diretório `\tmp` dentro de `\Windows\Temp` e depois cria uma cópia completa do banco do AD dentro desse diretório, com o nome de `temp.dit`.

Então vou fazer uma nova consulta usando essa informação: `index="main" sourcetype="wmic" username="*dean-admin*" "*temp.dit*" | table _time host username command result`

Explicando a consulta: Estamos procurando nos logs do wmic algum evento que venha do usuário dean-admin (a conta comprometida), que contenha a palavra "temp.dit" (a cópia) nele, e organizando a saída em uma tabela com as colunas de tempo, host (máquina), usuário, comando e resultado.

A resposta da consulta mostrou três eventos vindo da conta comprometida. Um deles é o que analisamos anteriormente, o segundo foi a ação de mover a cópia para o servidor web, e o primeiro é a compactação do arquivo, onde podemos ver a senha que foi usada `d5ag0nm@5t3r`.

![Execução](img/3-c.jpeg)

### 4. Persistence

![Persistência](img/4.jpeg)
![Persistência](img/4-a.jpeg)
![Persistência](img/4-b.jpeg)

### 5. Defense Evasion

![Evasão de Defesa](img/5.jpeg)
![Evasão de Defesa](img/5-a.jpeg)
![Evasão de Defesa](img/5-aa.jpeg)
![Evasão de Defesa](img/5-b.jpeg)
![Evasão de Defesa](img/5-ba.jpeg)
![Evasão de Defesa](img/5-c.jpeg)

### 6. Credential Access

![Acesso Credencial](img/6.jpeg)
![Acesso Credencial](img/6-a.jpeg)
![Acesso Credencial](img/6-b.jpeg)
![Acesso Credencial](img/6-ba.jpeg)
![Acesso Credencial](img/6-bb.jpeg)

### 7. Discovery & Lateral Movement

![Descoberta e Movimentação lateral](img/7.jpeg)
![Descoberta e Movimentação lateral](img/7-a.jpeg)
![Descoberta e Movimentação lateral](img/7-aa.jpeg)
![Descoberta e Movimentação lateral](img/7-b.jpeg)
![Descoberta e Movimentação lateral](img/7-ba.jpeg)
![Descoberta e Movimentação lateral](img/7-bb.jpeg)
![Descoberta e Movimentação lateral](img/7-bc.jpeg)

### 8. Collection

![Coleção](img/8.jpeg)
![Coleção](img/8-a.jpeg)
![Coleção](img/8-aa.jpeg)
![Coleção](img/8-ab.jpeg)

### 9. C2 & Cleanup

![C2 e Limpeza](img/9.jpeg)
![C2 e Limpeza](img/9-a.jpeg)
![C2 e Limpeza](img/9-b.jpeg)
![C2 e Limpeza](img/9-ba.jpeg)




