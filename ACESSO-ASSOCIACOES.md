# Acesso de usuários por associação

- Administradores mantêm acesso a todas as associações e podem vincular gestores a uma ou mais associações no cadastro de usuários.
- Gestores visualizam e alteram somente registros vinculados às associações selecionadas. O servidor aplica o escopo também nas rotas de carregamento e gravação; filtros da interface não são uma barreira de segurança.
- A tabela `users` mantém `filialId` para compatibilidade com versões anteriores e persiste as novas vinculações em `filialIds`. Ao iniciar, o servidor migra automaticamente o valor antigo para a lista quando necessário.
- A API continua aceitando `filialId` no cadastro/edição de gestores legados; novos clientes devem enviar `filialIds` como lista.

Execute `npm test` para validar login, cadastro multiassociação, compatibilidade com o campo antigo, filtragem de leitura e bloqueio de gravações fora do escopo.
