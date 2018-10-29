/*
	HTTP Proxy can proxy HTTP and HTTPS connections.
	Copyright (C) 2016-2018 Eric Kutcher

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _LITE_ADVAPI32_H
#define _LITE_ADVAPI32_H

#define STRICT
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <wincrypt.h>

//#define ADVAPI32_USE_STATIC_LIB

#ifdef ADVAPI32_USE_STATIC_LIB

	//__pragma( comment( lib, "advapi32.lib" ) )

	#define _CryptAcquireContextW	CryptAcquireContextW
	#define _CryptGenRandom			CryptGenRandom
	#define _CryptReleaseContext	CryptReleaseContext

	#define _CryptCreateHash		CryptCreateHash
	#define _CryptDestroyHash		CryptDestroyHash

	#define _CryptGetHashParam		CryptGetHashParam

	#define _CryptHashData			CryptHashData

	//#define _GetUserNameW			GetUserNameW

	#define _CryptDestroyKey		CryptDestroyKey
	#define _CryptImportKey			CryptImportKey

#else

	#define ADVAPI32_STATE_SHUTDOWN		0
	#define ADVAPI32_STATE_RUNNING		1

	typedef BOOL ( WINAPI *pCryptAcquireContextW )( HCRYPTPROV *phProv, LPCTSTR pszContainer, LPCTSTR pszProvider, DWORD dwProvType, DWORD dwFlags );
	typedef BOOL ( WINAPI *pCryptGenRandom )( HCRYPTPROV hProv, DWORD dwLen, BYTE *pbBuffer );
	typedef BOOL ( WINAPI *pCryptReleaseContext )( HCRYPTPROV hProv, DWORD dwFlags );

	typedef BOOL ( WINAPI *pCryptCreateHash )( HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH *phHash );
	typedef BOOL ( WINAPI *pCryptDestroyHash )( HCRYPTHASH hHash );

	typedef BOOL ( WINAPI *pCryptGetHashParam )( HCRYPTHASH hHash, DWORD dwParam, BYTE *pbData, DWORD *pdwDataLen, DWORD dwFlags );

	typedef BOOL ( WINAPI *pCryptHashData )( HCRYPTHASH hHash, BYTE *pbData, DWORD dwDataLen, DWORD dwFlags );

	//typedef BOOL ( WINAPI *pGetUserNameW )( LPTSTR lpBuffer, LPDWORD lpnSize );

	typedef BOOL ( WINAPI *pCryptDestroyKey )( HCRYPTKEY hKey );
	typedef BOOL ( WINAPI *pCryptImportKey )( HCRYPTPROV hProv, BYTE *pbData, DWORD dwDataLen, HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY *phKey );

	extern pCryptAcquireContextW	_CryptAcquireContextW;
	extern pCryptGenRandom			_CryptGenRandom;
	extern pCryptReleaseContext		_CryptReleaseContext;

	extern pCryptCreateHash			_CryptCreateHash;
	extern pCryptDestroyHash		_CryptDestroyHash;

	extern pCryptGetHashParam		_CryptGetHashParam;

	extern pCryptHashData			_CryptHashData;

	//extern pGetUserNameW			_GetUserNameW;

	extern pCryptDestroyKey			_CryptDestroyKey;
	extern pCryptImportKey			_CryptImportKey;

	extern unsigned char advapi32_state;

	bool InitializeAdvApi32();
	bool UnInitializeAdvApi32();

#endif

#endif
