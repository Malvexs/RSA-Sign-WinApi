#include <windows.h>
#include <stdio.h>
#include <wincrypt.h>

#define RSA2048BIT_KEY 0x08000000
#define RSA4096BIT_KEY 0x10000000
#define RSA8192BIT_KEY 0x20000000
#define RSA16384BIT_KEY 0x40000000

static void callerror(const char *mensagem);
static void ExportKeyToFile(HCRYPTKEY hkey, DWORD dwBlobType, LPCSTR filename);

int main(int argc, char *argv[]){

    if(argc < 2){
        printf("Argumentos invalidos\n");
        printf("Use: genkey keylengh\n");
        return 0;
    }

    HCRYPTHASH hhash;
    HCRYPTPROV hprov;
    HCRYPTKEY hkey;

    if(!CryptAcquireContext(&hprov, "Conteiner", NULL, PROV_RSA_FULL, 0)){
        if(CryptAcquireContext(&hprov, "Conteiner", NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET)){
            printf("[+]Conteiner Criado\n");
        }else{
            CryptReleaseContext(hprov, 0);
            callerror("Conteiner nao inicializado");
        }
    }else
        printf("[+]Conteiner Carregado\n\n");

    printf("Gerando RSA key: %s bytes...\n\n", argv[1]);

    if(!strcmp("1024", argv[1])){
        CryptGenKey(hprov, CALG_RSA_SIGN, RSA1024BIT_KEY|CRYPT_EXPORTABLE, &hkey);
    }else if(!strcmp("2048", argv[1])){
        CryptGenKey(hprov, CALG_RSA_SIGN, RSA2048BIT_KEY|CRYPT_EXPORTABLE, &hkey);
    }else if(!strcmp("4096", argv[1])){
        CryptGenKey(hprov, CALG_RSA_SIGN, RSA4096BIT_KEY|CRYPT_EXPORTABLE, &hkey);
    }else if(!strcmp("8192", argv[1])){
        CryptGenKey(hprov, CALG_RSA_SIGN, RSA8192BIT_KEY|CRYPT_EXPORTABLE, &hkey);
    }else if(!strcmp("16384", argv[1])){
        CryptGenKey(hprov, CALG_RSA_SIGN, RSA16384BIT_KEY|CRYPT_EXPORTABLE, &hkey);
    }else{
        CryptReleaseContext(hprov, 0);
        callerror("tamanho da chave invalido");
    }

    if(GetLastError() != 1008){
        callerror("nao foi possivel gerar o par de chaves");
    }

    printf("[+]RSA key gerada com sucesso\n", argv[1]);

    //
    ExportKeyToFile(hkey, PUBLICKEYBLOB, "publickey.h");
    ExportKeyToFile(hkey, PRIVATEKEYBLOB, "privatekey.h");

    if(CryptDestroyKey(hkey))
        printf("[+]Key destruida da memoria\n");
    CryptAcquireContext(&hprov, "Conteiner", NULL, PROV_RSA_FULL, CRYPT_DELETEKEYSET);
    CryptReleaseContext(hprov, 0);

}

static void callerror(const char *mensagem){

    printf("Error: %s %x\n", mensagem, GetLastError());
    exit(0);

}

static void ExportKeyToFile(HCRYPTKEY hkey, DWORD type, LPCSTR filename){

    PBYTE rsakey;
    DWORD rsakeylengh;

    FILE *filetowrite = fopen(filename, "wb");

    if(!filetowrite){
        fclose(filetowrite);
        callerror(filename);
    }else{
        fprintf(filetowrite, "/*\n");
        fprintf(filetowrite, "CHAVES RSA\n");
        if(type == PUBLICKEYBLOB)
            fprintf(filetowrite, "ARQUIVO DE CHAVE PUBLICADA\n");
        else if(type == PRIVATEKEYBLOB )
            fprintf(filetowrite, "ARQUIVO DE CHAVE PRIVADA E PUBLICA\n");
        fprintf(filetowrite, "*/");
    }

    if(CryptExportKey(hkey, 0, type, 0, 0, &rsakeylengh)){
        rsakey = (PBYTE) malloc(rsakeylengh);
        if(CryptExportKey(hkey, 0, type, 0, rsakey, &rsakeylengh)){

            fprintf(filetowrite, "\n\nstatic const char ", rsakeylengh);
            if(type == PUBLICKEYBLOB)
                fprintf(filetowrite, "publickey[%d] = {\n    ", rsakeylengh);
            else if(type == PRIVATEKEYBLOB)
                fprintf(filetowrite, "privatekey[%d] = {\n    ", rsakeylengh);
            int y=0;
            for(int x=0; x<rsakeylengh; x++){
                if(y == 15){
                    y = 0;
                    fprintf(filetowrite, "\n    ");
                }
                if(x == rsakeylengh-1){
                    fprintf(filetowrite, "0x%02X\n};", rsakey[x]);
                }else
                    fprintf(filetowrite, "0x%02X, ", rsakey[x]);

                y++;
            }

            printf("[+]Key exportada com sucesso: %s \n", filename);
        }else{
            callerror(filename);
        }
    }else
        callerror(filename);

    fclose(filetowrite);
}
