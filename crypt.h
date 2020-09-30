#ifndef RSA_SIGN_H_INCLUDED
#define RSA_SIGN_H_INCLUDED

#include <WinSock2.h>
#include <windows.h>
#include "commands.h"

BOOL CryptValidSign(PBYTE msgunsign, DWORD msgunsignlengh, PBYTE msgsign, DWORD msgsignlengh);
BOOL CryptCreateSign(PBYTE msgunsign, DWORD msgunsignlengh, PBYTE msgsign, PDWORD msgsignlengh);
BOOL CryptGenFileSign(LPCSTR file_name, COMMAND_HEADER cmd_h);

#endif // RSA_SIGN_H_INCLUDED
