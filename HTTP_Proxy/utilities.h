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

#ifndef _UTILITIES_H
#define _UTILITIES_H

#define MD5_LENGTH	16

struct AUTH_INFO
{
	char					*auth_start;
	char					*auth_end;
	char					*basic_encode;
	char					*basic_encode_end;
	char					*username;
	char					*username_end;
	char					*realm;
	char					*realm_end;
	char					*nonce;
	char					*nonce_end;
	char					*uri;
	char					*uri_end;
	char					*response;
	char					*response_end;
	char					*opaque;
	char					*opaque_end;
	char					*qop;
	char					*qop_end;
	char					*cnonce;
	char					*cnonce_end;
	unsigned int			nc;
	char					qop_type;		// 0 = not found, 1 = auth, 2 = auth-int, 3 = unhandled
	char					algorithm;		// 0 = not found, 1 = MD5, 2 = MD5-sess, 3 = unhandled
};

void encode_cipher( char *buffer, int buffer_length );
void decode_cipher( char *buffer, int buffer_length );

void CreateBasicAuthentication( char *username, unsigned long username_length, char *password, unsigned long password_length, char **authentication, unsigned long &authentication_length );
void CreateDigestInfo( char **nonce, unsigned long &nonce_length, char **opaque, unsigned long &opaque_length );

bool VerifyBasicAuthorization( char *encoded_credentials, unsigned long encoded_credientials_length, AUTH_INFO *auth_info );
bool VerifyDigestAuthorization( char *username, unsigned long username_length, char *password, unsigned long password_length, char *nonce, unsigned long nonce_length, char *opaque, unsigned long opaque_length, char *method, unsigned long method_length, AUTH_INFO *auth_info );

char *GlobalStrDupA( const char *_Str );
unsigned long long strtoull( char *str, bool base16 = false );
__int64 htonll( __int64 i );
char *url_decode( char *str, unsigned int str_len, unsigned int *dec_len );

int _printf( const char *_Format, ... );
int _wprintf( const wchar_t *_Format, ... );

unsigned char CountIntegerDigits( unsigned int integer );

#endif
