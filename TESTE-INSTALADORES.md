# Instaladores Windows 2.0.0

Há dois builds separados porque o Electron atual já não suporta Windows 7:

- **Windows atual x64:** `npm run dist` (ou `npm run dist:x64`) gera `release/installers/AcademiaPro+-Setup-2.0.0-x64.exe`. Usa a versão atual do Electron declarada no projeto e requer Windows 10 ou posterior. Este instalador não é compatível com Windows 7.
- **Windows 7 SP1 x86 (32 bits):** `npm run dist:windows7-x86` gera `release/legacy-windows7-x86/AcademiaPro+-Windows7-x86-2.0.0.exe`. Usa Electron 22.3.27, a última linha do Electron compatível com Windows 7, e Express 4.21.2 no pacote legado. As dependências do aplicativo moderno não são alteradas.

Não existe instalador x86 para o Electron moderno: o alvo x86 é exclusivamente o build legado de Windows 7. O instalador moderno x64 destina-se a Windows x64 atual; não o use como alternativa para Windows 7.

## Limitações importantes do Windows 7

Electron 22 e Windows 7 estão sem suporte e sem atualizações de segurança. O build Windows 7 é mantido somente por compatibilidade e ainda precisa ser instalado e exercitado em uma máquina ou VM Windows 7 SP1 x86 para comprovar compatibilidade real com esse sistema operacional. Não use essa versão com dados pessoais ou financeiros reais. O perfil/banco legado fica isolado em `%APPDATA%\AcademiaPro+-Windows7-Experimental\ia32`.

## Primeiro acesso

Cada build cria seu próprio banco SQLite vazio e inicia sempre na tela de login, solicitando autenticação novamente ao abrir o aplicativo. A versão atual usa `%APPDATA%\AcademiaPro+\x64\academia.sqlite`; o legado usa o perfil isolado indicado acima. Na primeira abertura, selecione **Criar administrador** na tela de login. A senha deve ter no mínimo oito caracteres, incluindo letra maiúscula, minúscula, número e símbolo. Não há contas padrão nem dados de demonstração.

O ícone da janela e dos instaladores é `Imagens/icone.ico`.

Os dados de instalações anteriores não são importados automaticamente para esses perfis. Bancos antigos não são removidos.

## Verificação

Execute `npm test` para verificar a versão e a separação dos alvos nos manifestos/scripts. Para validar a execução de ponta a ponta, instale e abra cada instalador no Windows-alvo correspondente, crie o administrador inicial, confirme que os registros começam vazios e reinicie para conferir a persistência. Para Windows 7, a validação em Windows 7 SP1 x86 é obrigatória; testar em Windows mais recente não substitui esse teste.
