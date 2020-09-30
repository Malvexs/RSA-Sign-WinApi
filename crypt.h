#ifndef RSA_SIGN_H_INCLUDED
#define RSA_SIGN_H_INCLUDED

#include <WinSock2.h>
#include <windows.h>

BOOL CryptValidSign(PBYTE msgunsign, DWORD msgunsignlengh, PBYTE msgsign, DWORD msgsignlengh);
BOOL CryptCreateSign(PBYTE msgunsign, DWORD msgunsignlengh, PBYTE msgsign, PDWORD msgsignlengh);

#endif // RSA_SIGN_H_INCLUDED
