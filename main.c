#include <stdio.h>
#include <windows.h>
#include "crypt.h"
#include "privatekey.h"
#include "publickey.h"

int main(int argc, char *argv[]){

    PCHAR Msgtosign = "Teste de assinatura";
    unsigned char Signmsg[4098];
    DWORD msgsignlengh;

    if(!CryptCreateSign(Msgtosign, strlen(Msgtosign), Signmsg, &msgsignlengh)){ //Criando assinatura e salvando no buffer "Signmsg"
        printf("[-]erro na assinatura\n");
        return -1;
    }else
        printf("[+]Msg assinada com sucesso\n");
    

    printf("Mensagem Assinada :\n");

    for(int x = 0;x<msgsignlengh;x++)
        printf("%02X ", Signmsg[x]);

    printf("\nFim da assinatura\n");

    if(!CryptValidSign(Msgtosign, strlen(Msgtosign), Signmsg, msgsignlengh)){ //Verificando a assinatura
        printf("[-]Assinatura invalida\n");
        return -1;
    }else
        printf("[+]Assinatura valida\n");
    

}
