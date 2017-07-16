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

#include "utilities.h"
#include "globals.h"
#include "lite_ntdll.h"
#include "lite_ws2_32.h"
#include "lite_advapi32.h"
#include "lite_crypt32.h"
#include "lite_shell32.h"

#include <limits.h>

#define ROTATE_LEFT( x, n ) ( ( ( x ) << ( n ) ) | ( ( x ) >> ( 8 - ( n ) ) ) )
#define ROTATE_RIGHT( x, n ) ( ( ( x ) >> ( n ) ) | ( ( x ) << ( 8 - ( n ) ) ) )

void encode_cipher( char *buffer, int buffer_length )
{
	int offset = buffer_length + 128;
	for ( int i = 0; i < buffer_length; ++i )
	{
		*buffer ^= ( unsigned char )buffer_length;
		*buffer = ( *buffer + offset ) % 256;
		*buffer = ROTATE_LEFT( ( unsigned char )*buffer, offset % 8 );

		buffer++;
		--offset;
	}
}

void decode_cipher( char *buffer, int buffer_length )
{
	int offset = buffer_length + 128;
	for ( int i = buffer_length; i > 0; --i )
	{
		*buffer = ROTATE_RIGHT( ( unsigned char )*buffer, offset % 8 );
		*buffer = ( *buffer - offset ) % 256;
		*buffer ^= ( unsigned char )buffer_length;

		buffer++;
		--offset;
	}
}

// Must use GlobalFree on this.
char *GlobalStrDupA( const char *_Str )
{
	if ( _Str == NULL )
	{
		return NULL;
	}

	size_t size = lstrlenA( _Str ) + sizeof( char );

	char *ret = ( char * )GlobalAlloc( GMEM_FIXED, size );

	if ( ret == NULL )
	{
		return NULL;
	}

	_memcpy_s( ret, size, _Str, size );

	return ret;
}

void GetMD5String( HCRYPTHASH *hHash, char **md5, DWORD *md5_length )
{
	DWORD cbHash = MD5_LENGTH;
	BYTE Hash[ MD5_LENGTH ];

	*md5 = NULL;
	*md5_length = 0;

	if ( _CryptGetHashParam( *hHash, HP_HASHVAL, Hash, &cbHash, 0 ) )
	{
		*md5_length = cbHash * 2;
		*md5 = ( char * )GlobalAlloc( GPTR, sizeof( char ) * ( *md5_length + 1 ) );

		CHAR digits[] = "0123456789abcdef";
		for ( DWORD i = 0; i < cbHash; ++i )
		{
			__snprintf( *md5 + ( 2 * i ), *md5_length - ( 2 * i ), "%c%c", digits[ Hash[ i ] >> 4 ], digits[ Hash[ i ] & 0xF ] );
		}
		*( *md5 + *md5_length ) = 0;	// Sanity.
	}
}

void CreateDigestInfo( char **nonce, unsigned long &nonce_length, char **opaque, unsigned long &opaque_length )
{
	char *HA1 = NULL;

	if ( *nonce != NULL )
	{
		GlobalFree( *nonce );
		*nonce = NULL;
	}

	nonce_length = 0;

	if ( *opaque != NULL )
	{
		GlobalFree( *opaque );
		*opaque = NULL;
	}

	opaque_length = 0;

	HCRYPTPROV hProv = NULL;
	if ( _CryptAcquireContextW( &hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT ) )
	{
		HCRYPTHASH hHash = NULL;

		BYTE rbuffer[ 16 ];

		if ( _CryptCreateHash( hProv, CALG_MD5, 0, 0, &hHash ) )
		{
			_CryptGenRandom( hProv, 16, ( BYTE * )&rbuffer );

			_CryptHashData( hHash, rbuffer, 16, 0 );

			GetMD5String( &hHash, nonce, &nonce_length );
		}

		if ( hHash != NULL )
		{
			_CryptDestroyHash( hHash );
			hHash = NULL;
		}

		if ( _CryptCreateHash( hProv, CALG_MD5, 0, 0, &hHash ) )
		{
			_CryptGenRandom( hProv, 16, ( BYTE * )&rbuffer );

			_CryptHashData( hHash, rbuffer, 16, 0 );

			GetMD5String( &hHash, opaque, &opaque_length );
		}

		if ( hHash != NULL )
		{
			_CryptDestroyHash( hHash );
		}
	}

	if ( hProv != NULL )
	{
		_CryptReleaseContext( hProv, 0 );
	}

	GlobalFree( HA1 );
}

void CreateBasicAuthentication( char *username, unsigned long username_length, char *password, unsigned long password_length, char **authentication, unsigned long &authentication_length )
{
	int concatenated_offset = 0;

	if ( *authentication != NULL )
	{
		GlobalFree( *authentication );
		*authentication = NULL;
	}

	authentication_length = 0;

	// username:password
	int concatenated_authentication_length = username_length + 1 + password_length;
	char *concatenated_authentication = ( char * )GlobalAlloc( GMEM_FIXED, sizeof( char ) * ( concatenated_authentication_length + 1 ) );

	if ( username != NULL )
	{
		_memcpy_s( concatenated_authentication, concatenated_authentication_length + 1, username, username_length );
		concatenated_offset += username_length;
	}

	concatenated_authentication[ concatenated_offset++ ] = ':';

	if ( password != NULL )
	{
		_memcpy_s( concatenated_authentication + concatenated_offset, ( concatenated_authentication_length + 1 ) - concatenated_offset, password, password_length );
		concatenated_offset += password_length;
	}

	concatenated_authentication[ concatenated_offset ] = 0;	// Sanity.

	_CryptBinaryToStringA( ( BYTE * )concatenated_authentication, concatenated_authentication_length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &authentication_length );

	*authentication = ( char * )GlobalAlloc( GMEM_FIXED, sizeof( char ) * authentication_length );
	_CryptBinaryToStringA( ( BYTE * )concatenated_authentication, concatenated_authentication_length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, ( LPSTR )( *authentication ), &authentication_length );
	*( ( *authentication ) + authentication_length ) = 0; // Sanity.

	GlobalFree( concatenated_authentication );
}

bool VerifyBasicAuthorization( char *encoded_credentials, unsigned long encoded_credientials_length, AUTH_INFO *auth_info )
{
	// See if the keys match.
	if ( ( auth_info->basic_encode_end - auth_info->basic_encode ) == encoded_credientials_length &&
		 encoded_credentials != NULL &&
		 _memcmp( auth_info->basic_encode, encoded_credentials, encoded_credientials_length ) == 0 )
	{
		return true;
	}

	return false;
}

bool VerifyDigestAuthorization( char *username, unsigned long username_length, char *password, unsigned long password_length, char *nonce, unsigned long nonce_length, char *opaque, unsigned long opaque_length, char *method, unsigned long method_length, AUTH_INFO *auth_info )
{
	bool ret = false;

	char *HA1 = NULL;
	DWORD HA1_length = 0;

	char *HA2 = NULL;
	DWORD HA2_length = 0;

	char *response = NULL;
	DWORD response_length = 0;

	int cnonce_length = ( auth_info->cnonce_end - auth_info->cnonce );
	int realm_length = ( auth_info->realm_end - auth_info->realm );
	int uri_length = ( auth_info->uri_end - auth_info->uri );
	int qop_length = ( auth_info->qop_end - auth_info->qop );

	// We can verify realm, nonce, and opaque to ensure the client responded correctly.
	if ( ( auth_info->realm_end - auth_info->realm ) != 29 || _memcmp( auth_info->realm, "Proxy Authentication Required", 29 != 0 ) )
	{
		return false;
	}

	if ( ( auth_info->nonce_end - auth_info->nonce ) != nonce_length || _memcmp( auth_info->nonce, nonce, nonce_length ) != 0 )
	{
		return false;
	}

	if ( ( auth_info->opaque_end - auth_info->opaque ) != opaque_length || _memcmp( auth_info->opaque, opaque, opaque_length ) != 0 )
	{
		return false;
	}

	HCRYPTPROV hProv = NULL;
	if ( _CryptAcquireContextW( &hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT ) )
	{
		HCRYPTHASH hHash = NULL;

		// If auth_info->algorithm is not set, then assume it's MD5.

		// Create HA1.
		if ( _CryptCreateHash( hProv, CALG_MD5, 0, 0, &hHash ) )
		{
			_CryptHashData( hHash, ( BYTE * )username, username_length, 0 );
			_CryptHashData( hHash, ( BYTE * )":", 1, 0 );
			_CryptHashData( hHash, ( BYTE * )auth_info->realm, realm_length, 0 );
			_CryptHashData( hHash, ( BYTE * )":", 1, 0 );
			_CryptHashData( hHash, ( BYTE * )password, password_length, 0 );

			GetMD5String( &hHash, &HA1, &HA1_length );

			// MD5-sess
			if ( auth_info->algorithm == 2 )
			{
				if ( hHash != NULL )
				{
					_CryptDestroyHash( hHash );
					hHash = NULL;
				}

				if ( _CryptCreateHash( hProv, CALG_MD5, 0, 0, &hHash ) )
				{
					_CryptHashData( hHash, ( BYTE * )HA1, HA1_length, 0 );
					_CryptHashData( hHash, ( BYTE * )":", 1, 0 );
					_CryptHashData( hHash, ( BYTE * )nonce, nonce_length, 0 );
					_CryptHashData( hHash, ( BYTE * )":", 1, 0 );
					_CryptHashData( hHash, ( BYTE * )auth_info->cnonce, cnonce_length, 0 );

					GlobalFree( HA1 );
					HA1 = NULL;
					HA1_length = 0;

					GetMD5String( &hHash, &HA1, &HA1_length );
				}
			}
		}

		if ( hHash != NULL )
		{
			_CryptDestroyHash( hHash );
			hHash = NULL;
		}

		// Create HA2.
		if ( _CryptCreateHash( hProv, CALG_MD5, 0, 0, &hHash ) )
		{
			_CryptHashData( hHash, ( BYTE * )method, method_length, 0 );
			_CryptHashData( hHash, ( BYTE * )":", 1, 0 );
			_CryptHashData( hHash, ( BYTE * )auth_info->uri, uri_length, 0 );

			// auth-int
			// We're not supporting this.
			// We'd have to stream in the HTTP payload body and who knows how large that could be. Forget it!
			if ( auth_info->qop_type == 2 )
			{
				char *entity_body = NULL;
				int entity_body_length = 0;

				_CryptHashData( hHash, ( BYTE * )":", 1, 0 );
				_CryptHashData( hHash, ( BYTE * )entity_body, entity_body_length, 0 );
			}

			GetMD5String( &hHash, &HA2, &HA2_length );
		}

		if ( hHash != NULL )
		{
			_CryptDestroyHash( hHash );
			hHash = NULL;
		}

		// Create response.
		if ( _CryptCreateHash( hProv, CALG_MD5, 0, 0, &hHash ) )
		{
			_CryptHashData( hHash, ( BYTE * )HA1, HA1_length, 0 );
			_CryptHashData( hHash, ( BYTE * )":", 1, 0 );
			_CryptHashData( hHash, ( BYTE * )nonce, nonce_length, 0 );
			_CryptHashData( hHash, ( BYTE * )":", 1, 0 );

			if ( auth_info->qop_type != 0 )
			{
				char ncount[ 9 ];
				__snprintf( ncount, 9, "%08x", auth_info->nc );	// Hex must be lowercase.

				_CryptHashData( hHash, ( BYTE * )ncount, 8, 0 );
				_CryptHashData( hHash, ( BYTE * )":", 1, 0 );
				_CryptHashData( hHash, ( BYTE * )auth_info->cnonce, cnonce_length, 0 );
				_CryptHashData( hHash, ( BYTE * )":", 1, 0 );
				_CryptHashData( hHash, ( BYTE * )auth_info->qop, qop_length, 0 );
				_CryptHashData( hHash, ( BYTE * )":", 1, 0 );
			}

			_CryptHashData( hHash, ( BYTE * )HA2, HA2_length, 0 );

			GetMD5String( &hHash, &response, &response_length );
		}

		if ( hHash != NULL )
		{
			_CryptDestroyHash( hHash );
			hHash = NULL;
		}
	}

	if ( hProv != NULL )
	{
		_CryptReleaseContext( hProv, 0 );
	}

	GlobalFree( HA1 );
	GlobalFree( HA2 );

	if ( response != NULL )
	{
		if ( response_length == ( auth_info->response_end - auth_info->response ) && _StrCmpNA( response, auth_info->response, response_length ) == 0 )
		{
			ret = true;
		}

		GlobalFree( response );
	}

	return ret;
}

// Default is base 10.
unsigned long long strtoull( char *str, bool base16 )
{
	if ( str == NULL )
	{
		return 0;
	}

	char *p = str;

	ULARGE_INTEGER uli;
	uli.QuadPart = 0;

	unsigned char digit = 0;

	if ( !base16 )
	{
		while ( *p && ( *p >= '0' && *p <= '9' ) )
		{
			if ( uli.QuadPart > ( ULLONG_MAX / 10 ) )
			{
				uli.QuadPart = ULLONG_MAX;
				break;
			}

			uli.QuadPart *= 10;

			/*__asm
			{
				mov     eax, dword ptr [ uli.QuadPart + 4 ]
				cmp		eax, 0					;// See if our QuadPart's value extends to 64 bits.
				mov     ecx, 10					;// Store the base (10) multiplier (low order bits).
				jne     short hard10			;// If there are high order bits in QuadPart, then multiply/add high and low bits.

				mov     eax, dword ptr [ uli.QuadPart + 0 ]	;// Store the QuadPart's low order bits.
				mul     ecx						;// Multiply the low order bits.

				jmp		finish10				;// Store the results in our 64 bit value.

			hard10:

				push    ebx						;// Save value to stack.

				mul     ecx						;// Multiply the high order bits of QuadPart with the low order bits of base (10).
				mov     ebx, eax				;// Store the result.

				mov     eax, dword ptr [ uli.QuadPart + 0 ]	;// Store QuadPart's low order bits.
				mul     ecx						;// Multiply the low order bits of QuadPart with the low order bits of base (10). edx = high, eax = low
				add     edx, ebx				;// Add the low order bits (ebx) to the high order bits (edx).

				pop     ebx						;// Restore value from stack.

			finish10:

				mov		uli.HighPart, edx		;// Store the high order bits.
				mov		uli.LowPart, eax		;// Store the low order bits.
			}*/

			digit = *p - '0';

			if ( uli.QuadPart > ( ULLONG_MAX - digit ) )
			{
				uli.QuadPart = ULLONG_MAX;
				break;
			}

			uli.QuadPart += digit;

			++p;
		}
	}
	else
	{
		while ( *p )
		{
			if ( *p >= '0' && *p <= '9' )
			{
				digit = *p - '0';
			}
			else if ( *p >= 'a' && *p <= 'f' )
			{
				digit = *p - 'a' + 10;
			}
			else if ( *p >= 'A' && *p <= 'F' )
			{
				digit = *p - 'A' + 10;
			}
			else
			{
				break;
			}

			if ( uli.QuadPart > ( ULLONG_MAX / 16 ) )
			{
				uli.QuadPart = ULLONG_MAX;
				break;
			}

			uli.QuadPart *= 16;

			/*__asm
			{
				mov     eax, dword ptr [ uli.QuadPart + 4 ]
				cmp		eax, 0					;// See if our QuadPart's value extends to 64 bits.
				mov     ecx, 16					;// Store the base (16) multiplier (low order bits).
				jne     short hard16			;// If there are high order bits in QuadPart, then multiply/add high and low bits.

				mov     eax, dword ptr [ uli.QuadPart + 0 ]	;// Store the QuadPart's low order bits.
				mul     ecx						;// Multiply the low order bits.

				jmp		finish16				;// Store the results in our 64 bit value.

			hard16:

				push    ebx						;// Save value to stack.

				mul     ecx						;// Multiply the high order bits of QuadPart with the low order bits of base (16).
				mov     ebx, eax				;// Store the result.

				mov     eax, dword ptr [ uli.QuadPart + 0 ]	;// Store QuadPart's low order bits.
				mul     ecx						;// Multiply the low order bits of QuadPart with the low order bits of base (16). edx = high, eax = low
				add     edx, ebx				;// Add the low order bits (ebx) to the high order bits (edx).

				pop     ebx						;// Restore value from stack.

			finish16:

				mov		uli.HighPart, edx		;// Store the high order bits.
				mov		uli.LowPart, eax		;// Store the low order bits.
			}*/

			if ( uli.QuadPart > ( ULLONG_MAX - digit ) )
			{
				uli.QuadPart = ULLONG_MAX;
				break;
			}

			uli.QuadPart += digit;

			++p;
		}
	}

	return uli.QuadPart;
}

__int64 htonll( __int64 i )
{
	unsigned int t = 0;
	unsigned int b = 0;

	unsigned int v[ 2 ];

	_memcpy_s( v, sizeof( unsigned int ) * 2, &i, sizeof( unsigned __int64 ) );

	t = _htonl( v[ 0 ] );
	v[ 0 ] = _htonl( v[ 1 ] );
	v[ 1 ] = t;

	_memcpy_s( &i, sizeof( __int64 ), ( void * )v, sizeof( unsigned int ) * 2 );
	
	return i;

	//return ( ( __int64 )_htonl( i & 0xFFFFFFFFU ) << 32 ) | _htonl( ( __int64 )( i >> 32 ) );
}

char from_hex( char c )
{
	//_CharLowerBuffA( ( LPSTR )c, 1 );
	//return is_digit( *c ) ? *c - '0' : *c - 'a' + 10;

	if ( is_digit( c ) )
	{
		return c - '0';
	}
	else if ( c - 'a' + 0U < 6U )
	{
		return c - 'a' + 10;
	}
	else if ( c - 'A' + 0U < 6U )
	{
		return c - 'A' + 10;
	}

	return c;
}

bool is_hex( char c )
{
	//_CharLowerBuffA( ( LPSTR )c, 1 );
	//return ( is_digit( *c ) || ( *c - 'a' + 0U < 6U ) );

	return ( is_digit( c ) || ( c - 'a' + 0U < 6U ) || ( c - 'A' + 0U < 6U ) );
}

char *url_decode( char *str, unsigned int str_len, unsigned int *dec_len )
{
	char *pstr = str;
	char *buf = ( char * )GlobalAlloc( GMEM_FIXED, sizeof( char ) * ( str_len + 1 ) );
	char *pbuf = buf;

	while ( pstr < ( str + str_len ) )
	{
		if ( *pstr == '%' )
		{
			// Look at the next two characters.
			if ( ( ( pstr + 3 ) <= ( str + str_len ) ) )
			{
				// See if they're both hex values.
				if ( ( pstr[ 1 ] != NULL && is_hex( pstr[ 1 ] ) ) &&
					 ( pstr[ 2 ] != NULL && is_hex( pstr[ 2 ] ) ) )
				{
					*pbuf++ = from_hex( pstr[ 1 ] ) << 4 | from_hex( pstr[ 2 ] );
					pstr += 2;
				}
				else
				{
					*pbuf++ = *pstr;
				}
			}
			else
			{
				*pbuf++ = *pstr;
			}
		}
		else if ( *pstr == '+' )
		{ 
			*pbuf++ = ' ';
		}
		else
		{
			*pbuf++ = *pstr;
		}

		pstr++;
	}

	*pbuf = '\0';

	if ( dec_len != NULL )
	{
		*dec_len = pbuf - buf;
	}

	return buf;
}

int _printf( const char *_Format, ... )
{
	if ( g_hOutput != NULL )
	{
		DWORD written = 0;
		va_list arglist;

		va_start( arglist, _Format );

		//char buffer[ 4016 ];	// This is the largest we can set this buffer with a local stack size of 4096.
		char buffer[ 8192 ];

		int buffer_length = __vsnprintf( buffer, 8192, _Format, arglist );

		va_end( arglist );

		if ( buffer_length >= 0 && WriteConsoleA( g_hOutput, buffer, buffer_length, &written, NULL ) )
		{
			return written;
		}
		else
		{
			return -1;
		}
	}
	else
	{
		return -1;
	}
}

int _wprintf( const wchar_t *_Format, ... )
{
	if ( g_hOutput != NULL )
	{
		DWORD written = 0;
		va_list arglist;

		va_start( arglist, _Format );

		//wchar_t buffer[ 2008 ];	// This is the largest we can set this buffer with a local stack size of 4096.
		wchar_t buffer[ 8192 ];

		int buffer_length = __vsnwprintf( buffer, 8192, _Format, arglist );

		va_end( arglist );

		if ( buffer_length >= 0 && WriteConsoleW( g_hOutput, buffer, buffer_length, &written, NULL ) )
		{
			return written;
		}
		else
		{
			return -1;
		}
	}
	else
	{
		return -1;
	}
}

unsigned char CountIntegerDigits( unsigned int integer )
{
	return ( integer < 10 ? 1 : ( integer < 100 ? 2 : ( integer < 1000 ? 3 : ( integer < 10000 ? 4 : ( integer < 100000 ? 5 : ( integer < 1000000 ? 6 : ( integer < 10000000 ? 7 : ( integer < 100000000 ? 8 : ( integer < 1000000000 ? 9 : 10 ) ) ) ) ) ) ) ) );
}
