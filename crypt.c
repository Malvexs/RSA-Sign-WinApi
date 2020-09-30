
#include "crypt.h"
#include "publickey.h" //public key file
#include "privatekey.h"
#include "file.h"
#include <wincrypt.h>

BOOL CryptValidSign(PBYTE msgunsign, DWORD msgunsignlengh, PBYTE msgsign, DWORD msgsignlengh){

    HCRYPTPROV hprov;
    HCRYPTKEY hpublickey;
    HCRYPTHASH hhash;
    BOOL result;

    if(!CryptAcquireContextA(&hprov, NULL, NULL, PROV_RSA_FULL, 0))
        CryptAcquireContextA(&hprov, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET);

    CryptImportKey(hprov, (PBYTE) publickey, sizeof(publickey), 0, 0, &hpublickey);

    CryptCreateHash(hprov, CALG_SHA, 0, 0, &hhash);
    CryptHashData(hhash, msgunsign, msgunsignlengh, 0);

    result = CryptVerifySignatureA(hhash, msgsign, msgsignlengh, hpublickey, 0, 0);

    CryptDestroyKey(hpublickey);
    CryptDestroyHash(hhash);
    CryptReleaseContext(hprov, 0);

    return result;
}

BOOL CryptCreateSign(PBYTE msgunsign, DWORD msgunsignlengh, PBYTE msgsign, PDWORD msgsignlengh){

    HCRYPTPROV hprov;
    HCRYPTKEY hprivate;
    HCRYPTHASH hhash;
    BOOL result;

    if(!CryptAcquireContextA(&hprov, NULL, NULL, PROV_RSA_FULL, 0))
        CryptAcquireContextA(&hprov, NULL, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET);

    CryptImportKey(hprov, (PBYTE) privatekey, sizeof(privatekey), 0, 0, &hprivate);
    CryptCreateHash(hprov, CALG_SHA, 0, 0, &hhash);
    CryptHashData(hhash, msgunsign, msgunsignlengh, 0);

    CryptSignHashA(hhash, AT_SIGNATURE, 0, 0, 0, msgsignlengh);
    result = CryptSignHashA(hhash, AT_SIGNATURE, 0, 0, msgsign, msgsignlengh);

    CryptDestroyKey(hprivate);
    CryptDestroyHash(hhash);
    CryptReleaseContext(hprov, 0);

    return result;
}

