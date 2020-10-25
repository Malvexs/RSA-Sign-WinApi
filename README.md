# RSA-Sign-WinApi
Assinatura RSA Utilizando a WinApi

Compile o arquivo CryptGenRsaKeyFile.c separadamente para para criar pares de chaves(public e private) RSA.
Use: gcc CryptGenRsaKeyFile.c -o Genkeys.exe
Crie um par de chaves usando Genkeys.exe 1024 or 2048 or 4096 or 8192 or 16394 (Quanto maior a chave mais vai demorar para gerar

O arquivo Crypt.c contem as funções necessarias para assinatura e verificação de assinatura. 
Exemplos de utilização em main.c
