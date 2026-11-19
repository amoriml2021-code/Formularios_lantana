# Controle de Formulários – versão para servidor próprio

Sem dependências externas: só precisa do **Node.js 22.13 ou superior** (https://nodejs.org). Banco SQLite embutido.

## Como rodar
1. Extraia a pasta. No Windows, dê dois cliques em `iniciar.bat` (ou `npm start`).
2. Na primeira execução aparece no terminal a senha do usuário `admin`. Anote e troque em "Usuários".
   (Opcional: defina `ADMIN_PASSWORD` antes de iniciar.)
3. Acesse http://localhost:3000. Outros computadores da rede: http://IP-DO-SERVIDOR:3000
   Variáveis: `PORT`, `DB_FILE` (caminho do banco), `HTTPS=1` (se estiver atrás de HTTPS).

## O que é garantido no servidor/banco
- Login e senha individuais (hash scrypt), sessão de 8 h, bloqueio de 5 min após 5 erros.
- Perfis: admin, gestor, consulta, colaborador (colaborador só recebe os próprios dados, filtrados no servidor).
- Lançamentos e presenças: INSERT único por colaborador+formulário+data; UPDATE/DELETE bloqueados por gatilhos do SQLite.
- Retificação: só admin, com justificativa; o original permanece e o valor anterior/novo vão para a auditoria.
- Auditoria imutável: logins, tentativas negadas, cadastros, lançamentos, duplicidades, retificações.
- Backup: "Usuários > Baixar backup" (ou copie a pasta `data`).

## Importante
- Use HTTPS (proxy Nginx/IIS/Caddy) se acessar fora da rede interna.
- Ainda não há tela para ver a auditoria (tabela `audit`; rota admin /api/audit).
- Periodicidade semanal/mensal é tratada como diária; relatório só em CSV.
