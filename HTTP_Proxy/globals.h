/*
	HTTP Proxy can proxy HTTP and HTTPS connections.
	Copyright (C) 2016-2017 Eric Kutcher

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

#ifndef _GLOBALS_H
#define _GLOBALS_H

#define STRICT
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <process.h>
#include <wincrypt.h>

#include "lite_ntdll.h"

#define FILETIME_TICKS_PER_SECOND	10000000LL

#define _wcsicmp_s( a, b ) ( ( a == NULL && b == NULL ) ? 0 : ( a != NULL && b == NULL ) ? 1 : ( a == NULL && b != NULL ) ? -1 : lstrcmpiW( a, b ) )
#define _stricmp_s( a, b ) ( ( a == NULL && b == NULL ) ? 0 : ( a != NULL && b == NULL ) ? 1 : ( a == NULL && b != NULL ) ? -1 : lstrcmpiA( a, b ) )

#define SAFESTRA( s ) ( s != NULL ? s : "" )
#define SAFESTR2A( s1, s2 ) ( s1 != NULL ? s1 : ( s2 != NULL ? s2 : "" ) )

#define SAFESTRW( s ) ( s != NULL ? s : L"" )
#define SAFESTR2W( s1, s2 ) ( s1 != NULL ? s1 : ( s2 != NULL ? s2 : L"" ) )

#define is_digit( c ) ( c - '0' + 0U <= 9U )
#define is_digit_w( c ) ( c - L'0' + 0U <= 9U )

//
extern unsigned char cfg_proxy_type;
//
extern wchar_t *cfg_hostname_ip_address;
extern unsigned short cfg_port;

extern wchar_t *g_hostname_ip_address;

extern wchar_t *cfg_hostname_ip_address_s;
extern unsigned short cfg_port_s;

extern wchar_t *g_hostname_ip_address_s;
//

extern bool cfg_require_authentication;
extern unsigned char cfg_auth_type;

extern char *cfg_auth_username;
extern char *cfg_auth_password;
extern bool cfg_forward_authentication;

extern char *g_authentication_key;
extern unsigned long g_authentication_key_length;
extern unsigned long g_auth_username_length;
extern unsigned long g_auth_password_length;

extern char *g_nonce;
extern unsigned long g_nonce_length;
extern char *g_opaque;
extern unsigned long g_opaque_length;

//

extern bool cfg_require_authentication_s;
extern unsigned char cfg_auth_type_s;

extern char *cfg_auth_username_s;
extern char *cfg_auth_password_s;
extern bool cfg_forward_authentication_s;

extern char *g_authentication_key_s;
extern unsigned long g_authentication_key_length_s;
extern unsigned long g_auth_username_length_s;
extern unsigned long g_auth_password_length_s;

extern char *g_nonce_s;
extern unsigned long g_nonce_length_s;
extern char *g_opaque_s;
extern unsigned long g_opaque_length_s;

//
extern bool cfg_use_ssl;
extern unsigned char cfg_protocol;		// Default is 4 (TLS 1.2)
extern unsigned char cfg_certificate_type;
extern wchar_t *cfg_certificate_cer_file_name;
extern wchar_t *cfg_certificate_key_file_name;
extern wchar_t *cfg_certificate_pkcs_file_name;
extern wchar_t *cfg_certificate_pkcs_password;
extern bool cfg_pkcs_password_is_null;
extern bool cfg_decrypt_tunnel;
//
extern bool cfg_forward_connections;
extern wchar_t *cfg_forward_hostname_ip_address;
extern unsigned short cfg_forward_port;

extern wchar_t *g_forward_punycode_hostname_ip_address;

extern bool cfg_forward_connections_s;
extern wchar_t *cfg_forward_hostname_ip_address_s;
extern unsigned short cfg_forward_port_s;

extern wchar_t *g_forward_punycode_hostname_ip_address_s;
//
extern unsigned short cfg_timeout;
extern bool cfg_retry_client_timeout;
//
extern unsigned long cfg_thread_count;	// Default is 1.
extern unsigned long g_max_threads;		// Default is 2.
//

extern HCRYPTPROV g_hProvider;

extern HANDLE g_hOutput;				// Console output

extern CONSOLE_SCREEN_BUFFER_INFO ConsoleScreenBufferInfo;

extern CRITICAL_SECTION console_cs;

extern bool g_show_output;

#endif
