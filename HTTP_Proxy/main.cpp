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

#include "connection.h"
#include "utilities.h"
#include "file_operations.h"
#include "lite_advapi32.h"
#include "lite_crypt32.h"
#include "lite_rpcrt4.h"
#include "lite_shell32.h"
#include "lite_ws2_32.h"
#include "lite_normaliz.h"

#define ALPHA_NUM( c ) ( c - 0x60 )
#define WAKEUP_MASK( c ) ( 1 << ALPHA_NUM( c ) )

//
unsigned char cfg_proxy_type = PROXY_TYPE_UNKNOWN;			// 1 = HTTP, 2 = HTTPS, 3 = HTTP & HTTPS
//
wchar_t *cfg_hostname_ip_address = NULL;
unsigned short cfg_port = 8888;

wchar_t *g_hostname_ip_address = NULL;

wchar_t *cfg_hostname_ip_address_s = NULL;
unsigned short cfg_port_s = 9999;

wchar_t *g_hostname_ip_address_s = NULL;
//
bool cfg_forward_connections = false;
wchar_t *cfg_forward_hostname_ip_address = NULL;
unsigned short cfg_forward_port = 8888;

wchar_t *g_forward_punycode_hostname_ip_address = NULL;

bool cfg_forward_connections_s = false;
wchar_t *cfg_forward_hostname_ip_address_s = NULL;
unsigned short cfg_forward_port_s = 9999;

wchar_t *g_forward_punycode_hostname_ip_address_s = NULL;
//

bool cfg_require_authentication = false;
unsigned char cfg_auth_type = 0;

char *cfg_auth_username = NULL;
char *cfg_auth_password = NULL;
bool cfg_forward_authentication = false;

char *g_authentication_key = NULL;
unsigned long g_authentication_key_length = 0;
unsigned long g_auth_username_length = 0;
unsigned long g_auth_password_length = 0;

char *g_nonce = NULL;
unsigned long g_nonce_length = 0;
char *g_opaque = NULL;
unsigned long g_opaque_length = 0;

//

bool cfg_require_authentication_s = false;
unsigned char cfg_auth_type_s = 0;

char *cfg_auth_username_s  = NULL;
char *cfg_auth_password_s  = NULL;
bool cfg_forward_authentication_s  = false;

char *g_authentication_key_s  = NULL;
unsigned long g_authentication_key_length_s  = 0;
unsigned long g_auth_username_length_s  = 0;
unsigned long g_auth_password_length_s  = 0;

char *g_nonce_s  = NULL;
unsigned long g_nonce_length_s  = 0;
char *g_opaque_s  = NULL;
unsigned long g_opaque_length_s  = 0;

//
bool cfg_use_ssl = false;
unsigned char cfg_protocol = 2;				// Default is TLS 1.2
unsigned char cfg_certificate_type = 0;
wchar_t *cfg_certificate_cer_file_name = NULL;
wchar_t *cfg_certificate_key_file_name = NULL;
wchar_t *cfg_certificate_pkcs_file_name = NULL;
wchar_t *cfg_certificate_pkcs_password = NULL;
bool cfg_pkcs_password_is_null = false;
bool cfg_decrypt_tunnel = false;
//
unsigned short cfg_timeout = 30;			// Default is 30 seconds.
bool cfg_retry_client_timeout = false;
//
unsigned long cfg_thread_count = 1;			// Default is 1.
unsigned long g_max_threads = 2;			// Default is 2.
//

HCRYPTPROV g_hProvider = NULL;				// For random values.

HANDLE g_hOutput = NULL;					// Console output.
HANDLE g_hInput = NULL;						// Console input.

bool g_show_output = false;					// Display connection related output.

CRITICAL_SECTION console_cs;

CONSOLE_SCREEN_BUFFER_INFO ConsoleScreenBufferInfo;

BOOL WINAPI ConsoleHandler( DWORD signal )
{
    if ( signal == CTRL_C_EVENT || signal == CTRL_CLOSE_EVENT || CTRL_LOGOFF_EVENT || CTRL_SHUTDOWN_EVENT )
	{
		if ( ws2_32_state == WS2_32_STATE_RUNNING )
		{
			if ( !g_shutdown_server )
			{
				EnterCriticalSection( &console_cs );
				SetConsoleTextAttribute( g_hOutput, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY );
				_wprintf( L"*** Shutting Down Server And Quitting ***\r\n" );
				SetConsoleTextAttribute( g_hOutput, ConsoleScreenBufferInfo.wAttributes );
				LeaveCriticalSection( &console_cs );
			}

			g_shutdown_server = true;

			_WSASetEvent( g_hCleanupEvent[ 0 ] );
		}
		else	// If the the Winsock library isn't running, then just exit the program.
		{
			return FALSE;
		}
	}

    return TRUE;
}

void DisplayInfo()
{
	if ( cfg_proxy_type & PROXY_TYPE_HTTP )
	{
		_wprintf( L"HTTP proxy listening on: %s:%lu\r\n", cfg_hostname_ip_address, cfg_port );
		_wprintf( L"HTTP %sauthentication is %srequired and will %sbe forwarded.\r\n",
			 ( !cfg_require_authentication ? L"" : ( cfg_auth_type == AUTH_TYPE_BASIC ? L"Basic " : ( cfg_auth_type == AUTH_TYPE_DIGEST ? L"Digest " : L"" ) ) ),
				cfg_require_authentication ? L"" : L"not ",
				cfg_forward_authentication ? L"" : L"not " );
	}
	if ( cfg_proxy_type & PROXY_TYPE_HTTPS )
	{
		_wprintf( L"HTTPS proxy listening on: %s:%lu\r\n", cfg_hostname_ip_address_s, cfg_port_s );
		_wprintf( L"HTTPS %sauthentication is %srequired and will %sbe forwarded.\r\n",
			 ( !cfg_require_authentication_s ? L"" : ( cfg_auth_type_s == AUTH_TYPE_BASIC ? L"Basic " : ( cfg_auth_type_s == AUTH_TYPE_DIGEST ? L"Digest " : L"" ) ) ),
				cfg_require_authentication_s ? L"" : L"not ",
				cfg_forward_authentication_s ? L"" : L"not " );
	}
	_wprintf( L"SSL/TLS is %s.\r\n", cfg_use_ssl ? L"enabled" : L"disabled" );
	if ( cfg_use_ssl )
	{
		_wprintf( L"SSL/TLS protocol: %s\r\n", ( cfg_protocol == 4 ? L"TLS 1.2" :
											   ( cfg_protocol == 3 ? L"TLS 1.1" :
											   ( cfg_protocol == 2 ? L"TLS 1.0" :
											   ( cfg_protocol == 1 ? L"SSL 3.0" :
																	 L"SSL 2.0" ) ) ) ) );
		_wprintf( L"Certificate type: %s\r\n", ( cfg_certificate_type == 1 ? L"PKCS #12" : L"Public/Private Key Pair" ) );
		_wprintf( L"Decrypting SSL/TLS tunnel is %s.\r\n", ( cfg_decrypt_tunnel ? L"enabled" : L"disabled" ) );
	}
	if ( cfg_forward_connections )
	{
		_wprintf( L"HTTP connections are forwarded to: %s:%lu\r\n", cfg_forward_hostname_ip_address, cfg_forward_port );
	}
	if ( cfg_forward_connections_s )
	{
		_wprintf( L"HTTPS connections are forwarded to: %s:%lu\r\n", cfg_forward_hostname_ip_address_s, cfg_forward_port_s );
	}
	_wprintf( L"Connection timeout is %lu second(s).\r\n", cfg_timeout );
	_wprintf( L"Running with %lu connection thread(s).\r\n", cfg_thread_count );
}

bool ConfigurationPrompt()
{
	bool status = false;

	// NI_MAXHOST includes the NULL terminator (which ReadConsole won't include). We'll use the NULL terminator + 1 for the \r\n that ReadConsole terminates with.
	wchar_t console_buffer[ NI_MAXHOST + 1 ];

	DWORD read = 0;

	EnterCriticalSection( &console_cs );

	SetConsoleMode( g_hInput, ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT );

	SetConsoleTextAttribute( g_hOutput, FOREGROUND_GREEN | FOREGROUND_INTENSITY );
	_wprintf( L"--------------------------\r\n" \
			  L"     Configure Server     \r\n" \
			  L"--------------------------\r\n" );
	SetConsoleTextAttribute( g_hOutput, ConsoleScreenBufferInfo.wAttributes );


	// LOAD CONFIGURATION FILE //
	bool configuration_file = false;
	while ( true )
	{
		_wprintf( L"Load configuration file? (yes/no): " );
		ReadConsoleW( g_hInput, console_buffer, NI_MAXHOST + 1, &read, NULL );
		if ( read == 0 ) { goto CONFIG_QUIT; }

		if ( read == 5 && _StrCmpNIW( console_buffer, L"yes", 3 ) == 0 )
		{
			configuration_file = true;
			break;
		}
		else if ( read == 4 && _StrCmpNIW( console_buffer, L"no", 2 ) == 0 )
		{
			configuration_file = false;
			break;
		}
	}
	/////////////////////////////


	///// CONFIGURATION FILE /////
	if ( configuration_file )
	{
		_wprintf( L"Configuration file path: " );
		ReadConsoleW( g_hInput, console_buffer, NI_MAXHOST + 1, &read, NULL );
		if ( read == 0 ) { goto CONFIG_QUIT; }

		if ( read > 2 )
		{
			read -= 2;

			if ( read < MAX_PATH )
			{
				console_buffer[ read ] = 0;	// Sanity.

				// If we can read the configuration file, then exit the prompt.
				if ( read_config( console_buffer ) == 0 )
				{
					_wprintf( L"The configuration file has been loaded.\r\n" );

					DisplayInfo();

					goto CONFIG_END;
				}
				else
				{
					_wprintf( L"Unable to load the configuration file.\r\n" );
				}
			}
		}
	}
	/////////////////////////////


	//////// PROXY TYPE ////////
	while ( true )
	{
		_wprintf( L"Select the type of connections to proxy.\r\n  1: HTTP\r\n  2: HTTPS\r\n  3: HTTP and HTTPS\r\nSelection: " );
		ReadConsoleW( g_hInput, console_buffer, NI_MAXHOST + 1, &read, NULL );
		if ( read == 0 ) { goto CONFIG_QUIT; }

		if ( read == 3 )
		{
			if ( console_buffer[ 0 ] == L'1' )
			{
				cfg_proxy_type = PROXY_TYPE_HTTP;
				break;
			}
			else if ( console_buffer[ 0 ] == L'2' )
			{
				cfg_proxy_type = PROXY_TYPE_HTTPS;
				break;
			}
			else if ( console_buffer[ 0 ] == L'3' )
			{
				cfg_proxy_type = PROXY_TYPE_HTTP_AND_HTTPS;
				break;
			}
		}
	}
	/////////////////////////////


	// HTTP HOST / IP ADDRESS AND PORT //
	unsigned int port = 0;
	if ( cfg_proxy_type & PROXY_TYPE_HTTP )
	{
		////// HTTP HOST / IP ADDRESS //////
		_wprintf( L"HTTP listening hostname/IP address: " );
		ReadConsoleW( g_hInput, console_buffer, NI_MAXHOST + 1, &read, NULL );
		if ( read == 0 ) { goto CONFIG_QUIT; }

		if ( read > 2 )
		{
			read -= 2;

			if ( read < NI_MAXHOST )
			{
				console_buffer[ read ] = 0;	// Sanity.

				if ( cfg_hostname_ip_address != NULL )
				{
					GlobalFree( cfg_hostname_ip_address );
				}

				cfg_hostname_ip_address = ( wchar_t * )GlobalAlloc( GMEM_FIXED, sizeof( wchar_t ) * ( read + 1 ) );
				_wmemcpy_s( cfg_hostname_ip_address, read + 1, console_buffer, read );
				cfg_hostname_ip_address[ read ] = 0;	// Sanity.
			}
		}
		/////////////////////////////


		//////// GET THE HTTP PORT ////////
		port = 0;
		do
		{
			_wprintf( L"HTTP listening port (1-65535): " );
			ReadConsoleW( g_hInput, console_buffer, NI_MAXHOST + 1, &read, NULL );
			if ( read == 0 ) { goto CONFIG_QUIT; }

			if ( read > 2 )
			{
				read -= 2;

				if ( read <= 5 )
				{
					console_buffer[ read ] = 0;	// Sanity.

					port = _wcstoul( console_buffer, NULL, 10 );
				}
			}
		}
		while ( port < 1 || port > 65535 );

		cfg_port = ( unsigned short )port;
		/////////////////////////////


		// USE HTTP PROXY AUTHENTICATION //
		while ( true )
		{
			_wprintf( L"Require HTTP authentication? (yes/no): " );
			ReadConsoleW( g_hInput, console_buffer, NI_MAXHOST + 1, &read, NULL );
			if ( read == 0 ) { goto CONFIG_QUIT; }

			if ( read == 5 && _StrCmpNIW( console_buffer, L"yes", 3 ) == 0 )
			{
				cfg_require_authentication = true;
				break;
			}
			else if ( read == 4 && _StrCmpNIW( console_buffer, L"no", 2 ) == 0 )
			{
				cfg_require_authentication = false;
				break;
			}
		}
		/////////////////////////////


		//// HTTP AUTHENTICATION ////
		if ( cfg_require_authentication )
		{
			//////// AUTH TYPE ////////
			while ( true )
			{
				_wprintf( L"Select the type of HTTP authentication.\r\n  1: Basic\r\n  2: Digest\r\nSelection: " );
				ReadConsoleW( g_hInput, console_buffer, NI_MAXHOST + 1, &read, NULL );
				if ( read == 0 ) { goto CONFIG_QUIT; }

				if ( read == 3 )
				{
					if ( console_buffer[ 0 ] == L'1' )
					{
						cfg_auth_type = AUTH_TYPE_BASIC;
						break;
					}
					else if ( console_buffer[ 0 ] == L'2' )
					{
						cfg_auth_type = AUTH_TYPE_DIGEST;
						break;
					}
				}
			}
			/////////////////////////////


			wchar_t *username = NULL;
			wchar_t *password = NULL;

			////// USERNAME //////
			_wprintf( L"HTTP authentication username: " );
			ReadConsoleW( g_hInput, console_buffer, NI_MAXHOST + 1, &read, NULL );
			if ( read == 0 ) { goto CONFIG_QUIT; }

			if ( read > 2 )
			{
				read -= 2;

				if ( read < NI_MAXHOST )
				{
					console_buffer[ read ] = 0;	// Sanity.

					username = ( wchar_t * )GlobalAlloc( GMEM_FIXED, sizeof( wchar_t ) * ( read + 1 ) );
					_wmemcpy_s( username, read + 1, console_buffer, read );
					username[ read ] = 0;	// Sanity.
				}
			}
			/////////////////////////////


			////// PASSWORD //////
			_wprintf( L"HTTP authentication password: " );
			SetConsoleMode( g_hInput, ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT );
			ReadConsoleW( g_hInput, console_buffer, NI_MAXHOST + 1, &read, NULL );
			SetConsoleMode( g_hInput, ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT );
			if ( read == 0 ) { GlobalFree( username ); goto CONFIG_QUIT; }

			_wprintf( L"\r\n" );	// We need to print the newline since the input was not echoed.

			if ( read > 2 )
			{
				read -= 2;

				if ( read < NI_MAXHOST )
				{
					console_buffer[ read ] = 0;	// Sanity.

					password = ( wchar_t * )GlobalAlloc( GMEM_FIXED, sizeof( wchar_t ) * ( read + 1 ) );
					_wmemcpy_s( password, read + 1, console_buffer, read );
					password[ read ] = 0;	// Sanity.
				}
			}
			/////////////////////////////


			////// REPEAT PASSWORD //////
			_wprintf( L"Repeat HTTP authentication password: " );
			SetConsoleMode( g_hInput, ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT );
			ReadConsoleW( g_hInput, console_buffer, NI_MAXHOST + 1, &read, NULL );
			SetConsoleMode( g_hInput, ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT );
			if ( read == 0 ) { GlobalFree( username ); GlobalFree( password ); goto CONFIG_QUIT; }

			_wprintf( L"\r\n" );	// We need to print the newline since the input was not echoed.

			if ( read > 2 )
			{
				read -= 2;

				if ( read < NI_MAXHOST )
				{
					console_buffer[ read ] = 0;	// Sanity.

					// See if the passwords match.
					if ( _wcscmp( password, console_buffer ) == 0 )
					{
						if ( cfg_auth_username != NULL )
						{
							GlobalFree( cfg_auth_username );
						}

						g_auth_username_length = WideCharToMultiByte( CP_UTF8, 0, username, -1, NULL, 0, NULL, NULL );
						cfg_auth_username = ( char * )GlobalAlloc( GMEM_FIXED, sizeof( char ) * g_auth_username_length ); // Size includes the null character.
						g_auth_username_length = WideCharToMultiByte( CP_UTF8, 0, username, -1, cfg_auth_username, g_auth_username_length, NULL, NULL ) - 1;

						if ( cfg_auth_password != NULL )
						{
							GlobalFree( cfg_auth_password );
						}

						g_auth_password_length = WideCharToMultiByte( CP_UTF8, 0, password, -1, NULL, 0, NULL, NULL );
						cfg_auth_password = ( char * )GlobalAlloc( GMEM_FIXED, sizeof( char ) * g_auth_password_length ); // Size includes the null character.
						g_auth_password_length = WideCharToMultiByte( CP_UTF8, 0, password, -1, cfg_auth_password, g_auth_password_length, NULL, NULL ) - 1;
					}
					else
					{
						_wprintf( L"The passwords don't match. HTTP authentication will be disabled.\r\n" );

						cfg_require_authentication = false;
					}
				}
			}
			/////////////////////////////

			GlobalFree( username );
			GlobalFree( password );


			// FORWARD HTTP PROXY AUTHENTICATION //
			while ( true )
			{
				_wprintf( L"Forward HTTP authentication? (yes/no): " );
				ReadConsoleW( g_hInput, console_buffer, NI_MAXHOST + 1, &read, NULL );
				if ( read == 0 ) { goto CONFIG_QUIT; }

				if ( read == 5 && _StrCmpNIW( console_buffer, L"yes", 3 ) == 0 )
				{
					cfg_forward_authentication = true;
					break;
				}
				else if ( read == 4 && _StrCmpNIW( console_buffer, L"no", 2 ) == 0 )
				{
					cfg_forward_authentication = false;
					break;
				}
			}
			/////////////////////////////
		}
		/////////////////////////////


		// FORWARD HTTP CLIENT CONNECTIONS //
		while ( true )
		{
			_wprintf( L"Forward HTTP client connections? (yes/no): " );
			ReadConsoleW( g_hInput, console_buffer, NI_MAXHOST + 1, &read, NULL );
			if ( read == 0 ) { goto CONFIG_QUIT; }

			if ( read == 5 && _StrCmpNIW( console_buffer, L"yes", 3 ) == 0 )
			{
				cfg_forward_connections = true;
				break;
			}
			else if ( read == 4 && _StrCmpNIW( console_buffer, L"no", 2 ) == 0 )
			{
				cfg_forward_connections = false;
				break;
			}
		}

		if ( cfg_forward_connections )
		{
			////// HOST / IP ADDRESS //////
			_wprintf( L"Forward HTTP listening hostname/IP address: " );
			ReadConsoleW( g_hInput, console_buffer, NI_MAXHOST + 1, &read, NULL );
			if ( read == 0 ) { goto CONFIG_QUIT; }

			if ( read > 2 )
			{
				read -= 2;

				if ( read < NI_MAXHOST )
				{
					console_buffer[ read ] = 0;	// Sanity.

					if ( cfg_forward_hostname_ip_address != NULL )
					{
						GlobalFree( cfg_forward_hostname_ip_address );
					}

					cfg_forward_hostname_ip_address = ( wchar_t * )GlobalAlloc( GMEM_FIXED, sizeof( wchar_t ) * ( read + 1 ) );
					_wmemcpy_s( cfg_forward_hostname_ip_address, read + 1, console_buffer, read );
					cfg_forward_hostname_ip_address[ read ] = 0;	// Sanity.
				}
			}
			/////////////////////////////


			//////// GET THE PORT ////////
			port = 0;
			do
			{
				_wprintf( L"Forward HTTP listening port (1-65535): " );
				ReadConsoleW( g_hInput, console_buffer, NI_MAXHOST + 1, &read, NULL );
				if ( read == 0 ) { goto CONFIG_QUIT; }

				if ( read > 2 )
				{
					read -= 2;

					if ( read <= 5 )
					{
						console_buffer[ read ] = 0;	// Sanity.

						port = _wcstoul( console_buffer, NULL, 10 );
					}
				}
			}
			while ( ( port < 1 || port > 65535 ) && port != cfg_port );

			cfg_forward_port = ( unsigned short )port;
			/////////////////////////////
		}
		/////////////////////////////
	}
	/////////////////////////////


	// HTTPS HOST / IP ADDRESS AND PORT //
	if ( cfg_proxy_type & PROXY_TYPE_HTTPS )
	{
		////// HTTPS HOST / IP ADDRESS //////
		_wprintf( L"HTTPS listening hostname/IP address: " );
		ReadConsoleW( g_hInput, console_buffer, NI_MAXHOST + 1, &read, NULL );
		if ( read == 0 ) { goto CONFIG_QUIT; }

		if ( read > 2 )
		{
			read -= 2;

			if ( read < NI_MAXHOST )
			{
				console_buffer[ read ] = 0;	// Sanity.

				if ( cfg_hostname_ip_address_s != NULL )
				{
					GlobalFree( cfg_hostname_ip_address_s );
				}

				cfg_hostname_ip_address_s = ( wchar_t * )GlobalAlloc( GMEM_FIXED, sizeof( wchar_t ) * ( read + 1 ) );
				_wmemcpy_s( cfg_hostname_ip_address_s, read + 1, console_buffer, read );
				cfg_hostname_ip_address_s[ read ] = 0;	// Sanity.
			}
		}
		/////////////////////////////


		//////// GET THE HTTPS PORT ////////
		port = 0;
		do
		{
			_wprintf( L"HTTPS listening port (1-65535): " );
			ReadConsoleW( g_hInput, console_buffer, NI_MAXHOST + 1, &read, NULL );
			if ( read == 0 ) { goto CONFIG_QUIT; }

			if ( read > 2 )
			{
				read -= 2;

				if ( read <= 5 )
				{
					console_buffer[ read ] = 0;	// Sanity.

					port = _wcstoul( console_buffer, NULL, 10 );
				}
			}
		}
		while ( port < 1 || port > 65535 );

		cfg_port_s = ( unsigned short )port;
		/////////////////////////////


		// USE HTTPS PROXY AUTHENTICATION //
		while ( true )
		{
			_wprintf( L"Require HTTPS authentication? (yes/no): " );
			ReadConsoleW( g_hInput, console_buffer, NI_MAXHOST + 1, &read, NULL );
			if ( read == 0 ) { goto CONFIG_QUIT; }

			if ( read == 5 && _StrCmpNIW( console_buffer, L"yes", 3 ) == 0 )
			{
				cfg_require_authentication_s = true;
				break;
			}
			else if ( read == 4 && _StrCmpNIW( console_buffer, L"no", 2 ) == 0 )
			{
				cfg_require_authentication_s = false;
				break;
			}
		}
		/////////////////////////////


		//// HTTPS AUTHENTICATION ////
		if ( cfg_require_authentication_s )
		{
			//////// AUTH TYPE ////////
			while ( true )
			{
				_wprintf( L"Select the type of HTTPS authentication.\r\n  1: Basic\r\n  2: Digest\r\nSelection: " );
				ReadConsoleW( g_hInput, console_buffer, NI_MAXHOST + 1, &read, NULL );
				if ( read == 0 ) { goto CONFIG_QUIT; }

				if ( read == 3 )
				{
					if ( console_buffer[ 0 ] == L'1' )
					{
						cfg_auth_type_s = AUTH_TYPE_BASIC;
						break;
					}
					else if ( console_buffer[ 0 ] == L'2' )
					{
						cfg_auth_type_s = AUTH_TYPE_DIGEST;
						break;
					}
				}
			}
			/////////////////////////////


			wchar_t *username = NULL;
			wchar_t *password = NULL;

			////// USERNAME //////
			_wprintf( L"HTTPS authentication username: " );
			ReadConsoleW( g_hInput, console_buffer, NI_MAXHOST + 1, &read, NULL );
			if ( read == 0 ) { goto CONFIG_QUIT; }

			if ( read > 2 )
			{
				read -= 2;

				if ( read < NI_MAXHOST )
				{
					console_buffer[ read ] = 0;	// Sanity.

					username = ( wchar_t * )GlobalAlloc( GMEM_FIXED, sizeof( wchar_t ) * ( read + 1 ) );
					_wmemcpy_s( username, read + 1, console_buffer, read );
					username[ read ] = 0;	// Sanity.
				}
			}
			/////////////////////////////


			////// PASSWORD //////
			_wprintf( L"HTTPS authentication password: " );
			SetConsoleMode( g_hInput, ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT );
			ReadConsoleW( g_hInput, console_buffer, NI_MAXHOST + 1, &read, NULL );
			SetConsoleMode( g_hInput, ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT );
			if ( read == 0 ) { GlobalFree( username ); goto CONFIG_QUIT; }

			_wprintf( L"\r\n" );	// We need to print the newline since the input was not echoed.

			if ( read > 2 )
			{
				read -= 2;

				if ( read < NI_MAXHOST )
				{
					console_buffer[ read ] = 0;	// Sanity.

					password = ( wchar_t * )GlobalAlloc( GMEM_FIXED, sizeof( wchar_t ) * ( read + 1 ) );
					_wmemcpy_s( password, read + 1, console_buffer, read );
					password[ read ] = 0;	// Sanity.
				}
			}
			/////////////////////////////


			////// REPEAT PASSWORD //////
			_wprintf( L"Repeat HTTPS authentication password: " );
			SetConsoleMode( g_hInput, ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT );
			ReadConsoleW( g_hInput, console_buffer, NI_MAXHOST + 1, &read, NULL );
			SetConsoleMode( g_hInput, ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT );
			if ( read == 0 ) { GlobalFree( username ); GlobalFree( password ); goto CONFIG_QUIT; }

			_wprintf( L"\r\n" );	// We need to print the newline since the input was not echoed.

			if ( read > 2 )
			{
				read -= 2;

				if ( read < NI_MAXHOST )
				{
					console_buffer[ read ] = 0;	// Sanity.

					// See if the passwords match.
					if ( _wcscmp( password, console_buffer ) == 0 )
					{
						if ( cfg_auth_username_s != NULL )
						{
							GlobalFree( cfg_auth_username_s );
						}

						g_auth_username_length_s = WideCharToMultiByte( CP_UTF8, 0, username, -1, NULL, 0, NULL, NULL );
						cfg_auth_username_s = ( char * )GlobalAlloc( GMEM_FIXED, sizeof( char ) * g_auth_username_length_s ); // Size includes the null character.
						g_auth_username_length_s = WideCharToMultiByte( CP_UTF8, 0, username, -1, cfg_auth_username_s, g_auth_username_length_s, NULL, NULL ) - 1;

						if ( cfg_auth_password_s != NULL )
						{
							GlobalFree( cfg_auth_password_s );
						}

						g_auth_password_length_s = WideCharToMultiByte( CP_UTF8, 0, password, -1, NULL, 0, NULL, NULL );
						cfg_auth_password_s = ( char * )GlobalAlloc( GMEM_FIXED, sizeof( char ) * g_auth_password_length_s ); // Size includes the null character.
						g_auth_password_length_s = WideCharToMultiByte( CP_UTF8, 0, password, -1, cfg_auth_password_s, g_auth_password_length_s, NULL, NULL ) - 1;
					}
					else
					{
						_wprintf( L"The passwords don't match. HTTPS authentication will be disabled.\r\n" );

						cfg_require_authentication_s = false;
					}
				}
			}
			/////////////////////////////

			GlobalFree( username );
			GlobalFree( password );


			// FORWARD HTTP PROXY AUTHENTICATION //
			while ( true )
			{
				_wprintf( L"Forward HTTPS authentication? (yes/no): " );
				ReadConsoleW( g_hInput, console_buffer, NI_MAXHOST + 1, &read, NULL );
				if ( read == 0 ) { goto CONFIG_QUIT; }

				if ( read == 5 && _StrCmpNIW( console_buffer, L"yes", 3 ) == 0 )
				{
					cfg_forward_authentication_s = true;
					break;
				}
				else if ( read == 4 && _StrCmpNIW( console_buffer, L"no", 2 ) == 0 )
				{
					cfg_forward_authentication_s = false;
					break;
				}
			}
			/////////////////////////////
		}
		/////////////////////////////


		// FORWARD HTTPS CLIENT CONNECTIONS //
		while ( true )
		{
			_wprintf( L"Forward HTTPS client connections? (yes/no): " );
			ReadConsoleW( g_hInput, console_buffer, NI_MAXHOST + 1, &read, NULL );
			if ( read == 0 ) { goto CONFIG_QUIT; }

			if ( read == 5 && _StrCmpNIW( console_buffer, L"yes", 3 ) == 0 )
			{
				cfg_forward_connections_s = true;
				break;
			}
			else if ( read == 4 && _StrCmpNIW( console_buffer, L"no", 2 ) == 0 )
			{
				cfg_forward_connections_s = false;
				break;
			}
		}

		if ( cfg_forward_connections_s )
		{
			////// HOST / IP ADDRESS //////
			_wprintf( L"Forward HTTPS listening hostname/IP address: " );
			ReadConsoleW( g_hInput, console_buffer, NI_MAXHOST + 1, &read, NULL );
			if ( read == 0 ) { goto CONFIG_QUIT; }

			if ( read > 2 )
			{
				read -= 2;

				if ( read < NI_MAXHOST )
				{
					console_buffer[ read ] = 0;	// Sanity.

					if ( cfg_forward_hostname_ip_address_s != NULL )
					{
						GlobalFree( cfg_forward_hostname_ip_address_s );
					}

					cfg_forward_hostname_ip_address_s = ( wchar_t * )GlobalAlloc( GMEM_FIXED, sizeof( wchar_t ) * ( read + 1 ) );
					_wmemcpy_s( cfg_forward_hostname_ip_address_s, read + 1, console_buffer, read );
					cfg_forward_hostname_ip_address_s[ read ] = 0;	// Sanity.
				}
			}
			/////////////////////////////


			//////// GET THE PORT ////////
			port = 0;
			do
			{
				_wprintf( L"Forward HTTPS listening port (1-65535): " );
				ReadConsoleW( g_hInput, console_buffer, NI_MAXHOST + 1, &read, NULL );
				if ( read == 0 ) { goto CONFIG_QUIT; }

				if ( read > 2 )
				{
					read -= 2;

					if ( read <= 5 )
					{
						console_buffer[ read ] = 0;	// Sanity.

						port = _wcstoul( console_buffer, NULL, 10 );
					}
				}
			}
			while ( ( port < 1 || port > 65535 ) && port != cfg_port );

			cfg_forward_port_s = ( unsigned short )port;
			/////////////////////////////
		}
		/////////////////////////////
	}
	/////////////////////////////


	// RUN SERVER WITH SSL/TLS //
	while ( true )
	{
		_wprintf( L"Enable SSL/TLS? (yes/no): " );
		ReadConsoleW( g_hInput, console_buffer, NI_MAXHOST + 1, &read, NULL );
		if ( read == 0 ) { goto CONFIG_QUIT; }

		if ( read == 5 && _StrCmpNIW( console_buffer, L"yes", 3 ) == 0 )
		{
			cfg_use_ssl = true;
			break;
		}
		else if ( read == 4 && _StrCmpNIW( console_buffer, L"no", 2 ) == 0 )
		{
			cfg_use_ssl = false;
			break;
		}
	}
	/////////////////////////////


	///// CERTIFICATE TYPE /////
	if ( cfg_use_ssl )
	{
		while ( true )
		{
			_wprintf( L"Select the SSL/TLS version (1-5).\r\n  1: TLS 1.2\r\n  2: TLS 1.1\r\n  3: TLS 1.0\r\n  4: SSL 3.0\r\n  5: SSL 2.0\r\nSelection: " );
			ReadConsoleW( g_hInput, console_buffer, NI_MAXHOST + 1, &read, NULL );
			if ( read == 0 ) { goto CONFIG_QUIT; }

			if ( read == 3 )
			{
				if ( console_buffer[ 0 ] >= L'1' && console_buffer[ 0 ] <= L'5' )
				{
					cfg_protocol = L'5' - console_buffer[ 0 ];
					break;
				}
			}
		}

		while ( true )
		{
			_wprintf( L"Select the certificate type (1-2).\r\n  1: PKCS #12\r\n  2: Public/Private Key Pair\r\nSelection: " );
			ReadConsoleW( g_hInput, console_buffer, NI_MAXHOST + 1, &read, NULL );
			if ( read == 0 ) { goto CONFIG_QUIT; }

			if ( read == 3 )
			{
				if ( console_buffer[ 0 ] == L'1' )
				{
					cfg_certificate_type = 1;
					break;
				}
				else if ( console_buffer[ 0 ] == L'2' )
				{
					cfg_certificate_type = 2;
					break;
				}
			}
		}
	}
	/////////////////////////////


	///// CERTIFICATE FILE /////
	if ( cfg_use_ssl )
	{
		/////////////////////////////
		if ( cfg_certificate_type == 1 )
		{
			_wprintf( L"PKCS #12 file path: " );
			ReadConsoleW( g_hInput, console_buffer, NI_MAXHOST + 1, &read, NULL );
			if ( read == 0 ) { goto CONFIG_QUIT; }

			if ( read > 2 )
			{
				read -= 2;

				if ( read < MAX_PATH )
				{
					console_buffer[ read ] = 0;	// Sanity.

					cfg_certificate_pkcs_file_name = ( wchar_t * )GlobalAlloc( GMEM_FIXED, sizeof( wchar_t ) * ( read + 1 ) );
					_wmemcpy_s( cfg_certificate_pkcs_file_name, read + 1, console_buffer, read );
					cfg_certificate_pkcs_file_name[ read ] = 0;	// Sanity.

					bool use_password = false;
					while ( true )
					{
						_wprintf( L"Does the PKCS #12 file require a password? (yes/no): " );
						ReadConsoleW( g_hInput, console_buffer, NI_MAXHOST + 1, &read, NULL );
						if ( read == 0 ) { goto CONFIG_QUIT; }

						if ( read == 5 && _StrCmpNIW( console_buffer, L"yes", 3 ) == 0 )
						{
							use_password = true;
							break;
						}
						else if ( read == 4 && _StrCmpNIW( console_buffer, L"no", 2 ) == 0 )
						{
							use_password = false;
							break;
						}
					}

					if ( use_password )
					{
						_wprintf( L"PKCS #12 password: " );
						SetConsoleMode( g_hInput, ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT );
						ReadConsoleW( g_hInput, console_buffer, NI_MAXHOST + 1, &read, NULL );
						SetConsoleMode( g_hInput, ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT );
						if ( read == 0 ) { goto CONFIG_QUIT; }

						_wprintf( L"\r\n" );	// We need to print the newline since the input was not echoed.

						if ( read >= 2 )	// Include the empty string.
						{
							read -= 2;

							// The empty string "" is allowed.
							if ( read < NI_MAXHOST )	// Allows for a 1024 character + 1 NULL character password.
							{
								console_buffer[ read ] = 0;	// Sanity.

								if ( cfg_certificate_pkcs_password != NULL )
								{
									GlobalFree( cfg_certificate_pkcs_password );
								}

								cfg_certificate_pkcs_password = ( wchar_t * )GlobalAlloc( GMEM_FIXED, sizeof( wchar_t ) * ( read + 1 ) );
								_wmemcpy_s( cfg_certificate_pkcs_password, read + 1, console_buffer, read );
								cfg_certificate_pkcs_password[ read ] = 0;	// Sanity.

								cfg_pkcs_password_is_null = false;
							}
						}
					}
					else	// Use a NULL password.
					{
						cfg_pkcs_password_is_null = true;

						if ( cfg_certificate_pkcs_password != NULL )
						{
							GlobalFree( cfg_certificate_pkcs_password );
							cfg_certificate_pkcs_password = NULL;
						}
					}
				}
			}
		}
		else if ( cfg_certificate_type == 2 )
		{
			_wprintf( L"Public Key file path: " );
			ReadConsoleW( g_hInput, console_buffer, NI_MAXHOST + 1, &read, NULL );
			if ( read == 0 ) { goto CONFIG_QUIT; }

			if ( read > 2 )
			{
				read -= 2;

				if ( read < MAX_PATH )
				{
					console_buffer[ read ] = 0;	// Sanity.

					if ( cfg_certificate_cer_file_name != NULL )
					{
						GlobalFree( cfg_certificate_cer_file_name );
					}

					cfg_certificate_cer_file_name = ( wchar_t * )GlobalAlloc( GMEM_FIXED, sizeof( wchar_t ) * ( read + 1 ) );
					_wmemcpy_s( cfg_certificate_cer_file_name, read + 1, console_buffer, read );
					cfg_certificate_cer_file_name[ read ] = 0;	// Sanity.

					_wprintf( L"Private Key file path: " );
					ReadConsoleW( g_hInput, console_buffer, NI_MAXHOST + 1, &read, NULL );
					if ( read == 0 ) { goto CONFIG_QUIT; }

					if ( read > 2 )
					{
						read -= 2;

						if ( read < MAX_PATH )
						{
							console_buffer[ read ] = 0;	// Sanity.

							if ( cfg_certificate_key_file_name != NULL )
							{
								GlobalFree( cfg_certificate_key_file_name );
							}

							cfg_certificate_key_file_name = ( wchar_t * )GlobalAlloc( GMEM_FIXED, sizeof( wchar_t ) * ( read + 1 ) );
							_wmemcpy_s( cfg_certificate_key_file_name, read + 1, console_buffer, read );
							cfg_certificate_key_file_name[ read ] = 0;	// Sanity.
						}
					}
				}
			}
		}
		/////////////////////////////


		///// DECODE TUNNEL DATA /////
		while ( true )
		{
			_wprintf( L"Decrypt SSL/TLS tunnel? (yes/no): " );
			ReadConsoleW( g_hInput, console_buffer, NI_MAXHOST + 1, &read, NULL );
			if ( read == 0 ) { goto CONFIG_QUIT; }

			if ( read == 5 && _StrCmpNIW( console_buffer, L"yes", 3 ) == 0 )
			{
				cfg_decrypt_tunnel = true;
				break;
			}
			else if ( read == 4 && _StrCmpNIW( console_buffer, L"no", 2 ) == 0 )
			{
				cfg_decrypt_tunnel = false;
				break;
			}
		}
		/////////////////////////////
	}
	/////////////////////////////


	///// CONNECTION TIMEOUT /////
	unsigned int timeout = -1;
	do
	{
		_wprintf( L"Connection timeout in seconds: (1-300): " );
		ReadConsoleW( g_hInput, console_buffer, NI_MAXHOST + 1, &read, NULL );
		if ( read == 0 ) { goto CONFIG_QUIT; }

		if ( read > 2 )
		{
			read -= 2;

			if ( read <= 3 )
			{
				console_buffer[ read ] = 0;	// Sanity.

				bool is_valid_number = false;
				for ( unsigned char i = 0; i < read; ++i )
				{
					is_valid_number = is_digit_w( console_buffer[ i ] );
					if ( !is_valid_number )
					{
						break;
					}
				}

				if ( is_valid_number )
				{
					timeout = _wcstoul( console_buffer, NULL, 10 );
				}
			}
		}
	}
	while ( timeout < 0 || timeout > 300 );

	cfg_timeout = ( unsigned short )timeout;
	/////////////////////////////


	// RETRY CLIENT CONNECTION //
	while ( true )
	{
		_wprintf( L"Retry available client connections upon timeout? (yes/no): " );
		ReadConsoleW( g_hInput, console_buffer, NI_MAXHOST + 1, &read, NULL );
		if ( read == 0 ) { goto CONFIG_QUIT; }

		if ( read == 5 && _StrCmpNIW( console_buffer, L"yes", 3 ) == 0 )
		{
			cfg_retry_client_timeout = true;
			break;
		}
		else if ( read == 4 && _StrCmpNIW( console_buffer, L"no", 2 ) == 0 )
		{
			cfg_retry_client_timeout = false;
			break;
		}
	}
	/////////////////////////////


	///// GET THREAD COUNT /////
	unsigned int thread_count = 0;
	DWORD max_digits = CountIntegerDigits( g_max_threads );
	do
	{
		_wprintf( L"Server threads (1-%lu): ", g_max_threads );
		ReadConsoleW( g_hInput, console_buffer, NI_MAXHOST + 1, &read, NULL );
		if ( read == 0 ) { goto CONFIG_QUIT; }

		if ( read > 2 )
		{
			read -= 2;

			if ( read <= max_digits )
			{
				console_buffer[ read ] = 0;	// Sanity.

				thread_count = _wcstoul( console_buffer, NULL, 10 );
			}
		}
	}
	while ( thread_count < 1 || thread_count > g_max_threads );

	cfg_thread_count = thread_count;
	/////////////////////////////


	// SAVE CONFIGURATION FILE //
	configuration_file = false;
	while ( true )
	{
		_wprintf( L"Save configuration file? (yes/no): " );
		ReadConsoleW( g_hInput, console_buffer, NI_MAXHOST + 1, &read, NULL );
		if ( read == 0 ) { goto CONFIG_QUIT; }

		if ( read == 5 && _StrCmpNIW( console_buffer, L"yes", 3 ) == 0 )
		{
			configuration_file = true;
			break;
		}
		else if ( read == 4 && _StrCmpNIW( console_buffer, L"no", 2 ) == 0 )
		{
			configuration_file = false;
			break;
		}
	}
	/////////////////////////////


	///// CONFIGURATION FILE /////
	if ( configuration_file )
	{
		_wprintf( L"Configuration file path: " );
		ReadConsoleW( g_hInput, console_buffer, NI_MAXHOST + 1, &read, NULL );
		if ( read == 0 ) { goto CONFIG_QUIT; }

		if ( read > 2 )
		{
			read -= 2;

			if ( read < MAX_PATH )
			{
				console_buffer[ read ] = 0;	// Sanity.

				save_config( console_buffer );
			}
		}
	}
	/////////////////////////////

// The configuration was skipped because it was loaded from a file.
CONFIG_END:

	if ( normaliz_state == NORMALIZ_STATE_RUNNING )
	{
		int hostname_length = 0;
		int punycode_length = 0;

		if ( cfg_proxy_type & PROXY_TYPE_HTTP )
		{
			if ( g_hostname_ip_address != NULL )
			{
				GlobalFree( g_hostname_ip_address );
				g_hostname_ip_address = NULL;
			}

			hostname_length = lstrlenW( cfg_hostname_ip_address ) + 1;	// Include the NULL terminator.
			punycode_length = _IdnToAscii( 0, cfg_hostname_ip_address, hostname_length, NULL, 0 );

			if ( punycode_length > hostname_length )
			{
				g_hostname_ip_address = ( wchar_t * )GlobalAlloc( GMEM_FIXED, sizeof( wchar_t ) * punycode_length );
				_IdnToAscii( 0, cfg_hostname_ip_address, hostname_length, g_hostname_ip_address, punycode_length );
			}
		}

		if ( cfg_proxy_type & PROXY_TYPE_HTTPS )
		{
			if ( g_hostname_ip_address_s != NULL )
			{
				GlobalFree( g_hostname_ip_address_s );
				g_hostname_ip_address_s = NULL;
			}

			hostname_length = lstrlenW( cfg_hostname_ip_address_s ) + 1;	// Include the NULL terminator.
			punycode_length = _IdnToAscii( 0, cfg_hostname_ip_address_s, hostname_length, NULL, 0 );

			if ( punycode_length > hostname_length )
			{
				g_hostname_ip_address_s = ( wchar_t * )GlobalAlloc( GMEM_FIXED, sizeof( wchar_t ) * punycode_length );
				_IdnToAscii( 0, cfg_hostname_ip_address_s, hostname_length, g_hostname_ip_address_s, punycode_length );
			}
		}

		if ( cfg_forward_connections )
		{
			if ( g_forward_punycode_hostname_ip_address != NULL )
			{
				GlobalFree( g_forward_punycode_hostname_ip_address );
				g_forward_punycode_hostname_ip_address = NULL;
			}

			hostname_length = lstrlenW( cfg_forward_hostname_ip_address ) + 1;	// Include the NULL terminator.
			punycode_length = _IdnToAscii( 0, cfg_forward_hostname_ip_address, hostname_length, NULL, 0 );

			if ( punycode_length > hostname_length )
			{
				g_forward_punycode_hostname_ip_address = ( wchar_t * )GlobalAlloc( GMEM_FIXED, sizeof( wchar_t ) * punycode_length );
				_IdnToAscii( 0, cfg_forward_hostname_ip_address, hostname_length, g_forward_punycode_hostname_ip_address, punycode_length );
			}
		}

		if ( cfg_forward_connections_s )
		{
			if ( g_forward_punycode_hostname_ip_address_s != NULL )
			{
				GlobalFree( g_forward_punycode_hostname_ip_address_s );
				g_forward_punycode_hostname_ip_address_s = NULL;
			}

			hostname_length = lstrlenW( cfg_forward_hostname_ip_address_s ) + 1;	// Include the NULL terminator.
			punycode_length = _IdnToAscii( 0, cfg_forward_hostname_ip_address_s, hostname_length, NULL, 0 );

			if ( punycode_length > hostname_length )
			{
				g_forward_punycode_hostname_ip_address_s = ( wchar_t * )GlobalAlloc( GMEM_FIXED, sizeof( wchar_t ) * punycode_length );
				_IdnToAscii( 0, cfg_forward_hostname_ip_address_s, hostname_length, g_forward_punycode_hostname_ip_address_s, punycode_length );
			}
		}
	}

	if ( cfg_require_authentication )
	{
		if ( cfg_auth_type == AUTH_TYPE_BASIC )
		{
			CreateBasicAuthentication( cfg_auth_username, g_auth_username_length, cfg_auth_password, g_auth_password_length, &g_authentication_key, g_authentication_key_length );
		}
		else if ( cfg_auth_type == AUTH_TYPE_DIGEST )
		{
			CreateDigestInfo( &g_nonce, g_nonce_length, &g_opaque, g_opaque_length );
		}
	}

	if ( cfg_require_authentication_s )
	{
		if ( cfg_auth_type_s == AUTH_TYPE_BASIC )
		{
			CreateBasicAuthentication( cfg_auth_username_s, g_auth_username_length_s, cfg_auth_password_s, g_auth_password_length_s, &g_authentication_key_s, g_authentication_key_length_s );
		}
		else if ( cfg_auth_type_s == AUTH_TYPE_DIGEST )
		{
			CreateDigestInfo( &g_nonce_s, g_nonce_length_s, &g_opaque_s, g_opaque_length_s );
		}
	}

	SetConsoleTextAttribute( g_hOutput, FOREGROUND_GREEN | FOREGROUND_INTENSITY );
	_wprintf( L"--------------------------\r\n" \
			  L"  Configuration Complete  \r\n" \
			  L"--------------------------\r\n" );
	SetConsoleTextAttribute( g_hOutput, ConsoleScreenBufferInfo.wAttributes );

	status = true;

// User pressed CTRL+C
CONFIG_QUIT:

	_wprintf( L"\r\n" );

	LeaveCriticalSection( &console_cs );

	return status;
}

#ifndef NTDLL_USE_STATIC_LIB
int APIENTRY _WinMain()
#else
int APIENTRY WinMain( HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow )
#endif
{
	#ifndef NTDLL_USE_STATIC_LIB
		if ( !InitializeNTDLL() ){ goto UNLOAD_DLLS; }
	#endif
	#ifndef ADVAPI32_USE_STATIC_LIB
		if ( !InitializeAdvApi32() ){ goto UNLOAD_DLLS; }
	#endif
	#ifndef SHELL32_USE_STATIC_LIB
		if ( !InitializeShell32() ){ goto UNLOAD_DLLS; }
	#endif
	#ifndef CRYPT32_USE_STATIC_LIB
		if ( !InitializeCrypt32() ){ goto UNLOAD_DLLS; }
	#endif
	#ifndef NORMALIZ_USE_STATIC_LIB
		InitializeNormaliz();
	#endif

	/*// Get the new base directory if the user supplied a path.
	bool default_directory = true;
	int argCount = 0;
	LPWSTR *szArgList = _CommandLineToArgvW( GetCommandLineW(), &argCount );
	if ( szArgList != NULL )
	{
		// The first parameter is the path to the executable, second is our switch "-d", and third is the new base directory path.
		if ( argCount == 3 &&
			 szArgList[ 1 ][ 0 ] != 0 && szArgList[ 1 ][ 0 ] == L'-' && szArgList[ 1 ][ 1 ] != 0 && szArgList[ 1 ][ 1 ] == L'd' && szArgList[ 1 ][ 2 ] == 0 &&
			 GetFileAttributesW( szArgList[ 2 ] ) == FILE_ATTRIBUTE_DIRECTORY )
		{
			base_directory_length = lstrlenW( szArgList[ 2 ] );
			if ( base_directory_length >= MAX_PATH )
			{
				base_directory_length = MAX_PATH - 1;
			}
			_wmemcpy_s( base_directory, MAX_PATH, szArgList[ 2 ], base_directory_length );
			base_directory[ base_directory_length ] = 0;	// Sanity.

			default_directory = false;
		}

		// Free the parameter list.
		LocalFree( szArgList );
	}*/

	InitializeCriticalSection( &console_cs );

	if ( !SetConsoleCtrlHandler( ConsoleHandler, TRUE ) )
	{
		goto CLEANUP;
	}

	SYSTEM_INFO systemInfo;
	GetSystemInfo( &systemInfo );

	if ( systemInfo.dwNumberOfProcessors > 0 )
	{
		g_max_threads = systemInfo.dwNumberOfProcessors * 2;	// Default is 2.
		cfg_thread_count = systemInfo.dwNumberOfProcessors;		// Default is 1.
	}

	// Used for random numbers.
	if ( !_CryptAcquireContextW( &g_hProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT ) )
	{
		goto CLEANUP;
	}


	wchar_t console_buffer[ 16 ];
	DWORD read = 0;

	g_hOutput = GetStdHandle( STD_OUTPUT_HANDLE );

	GetConsoleScreenBufferInfo( g_hOutput, &ConsoleScreenBufferInfo );

	g_hInput = GetStdHandle( STD_INPUT_HANDLE );



	EnterCriticalSection( &console_cs );
	_wprintf( L"HTTP Proxy/Tunnel is made free under the GPLv3 license.\r\nVersion 1.0.0.0\r\nCopyright (c) 2016-2017 Eric Kutcher\r\n\r\n" );
	LeaveCriticalSection( &console_cs );


	if ( !ConfigurationPrompt() )
	{
		goto CLEANUP;	// User pressed CTRL+C
	}


	EnterCriticalSection( &console_cs );
	SetConsoleTextAttribute( g_hOutput, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY );
	_wprintf( L"*** Starting Server ***\r\n" );
	SetConsoleTextAttribute( g_hOutput, ConsoleScreenBufferInfo.wAttributes );
	LeaveCriticalSection( &console_cs );

	HANDLE server_thread = ( HANDLE )_CreateThread( NULL, 0, IOCPServer, NULL, 0, NULL );


	CONSOLE_READCONSOLE_CONTROL crcc;
	crcc.nLength = sizeof( CONSOLE_READCONSOLE_CONTROL );
	crcc.nInitialChars = 0;
	crcc.dwCtrlWakeupMask = 0xFFFFFFFF;//WAKEUP_MASK( L'q' ) | WAKEUP_MASK( L'f' ) | WAKEUP_MASK( L'r' ) | WAKEUP_MASK( L'e' ) | WAKEUP_MASK( L'o' );
	crcc.dwControlKeyState = 0;

	do
	{
		SetConsoleMode( g_hInput, ENABLE_PROCESSED_INPUT | ENABLE_LINE_INPUT );
		ReadConsoleW( g_hInput, console_buffer, 16, &read, &crcc );

		if ( console_buffer[ 0 ] == ALPHA_NUM( L'q' ) )
		{
			if ( ws2_32_state == WS2_32_STATE_RUNNING )
			{
				if ( !g_shutdown_server )
				{
					EnterCriticalSection( &console_cs );
					SetConsoleTextAttribute( g_hOutput, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY );
					_wprintf( L"*** Shutting Down Server And Quitting ***\r\n" );
					SetConsoleTextAttribute( g_hOutput, ConsoleScreenBufferInfo.wAttributes );
					LeaveCriticalSection( &console_cs );

					g_shutdown_server = true;

					_WSASetEvent( g_hCleanupEvent[ 0 ] );
				}
			}

			break;
		}
		else if ( console_buffer[ 0 ] == ALPHA_NUM( L'f' ) || console_buffer[ 0 ] == ALPHA_NUM( L'r' ) )
		{
			if ( ws2_32_state == WS2_32_STATE_RUNNING )
			{
				// If the server has already been shut down, then spawn the server thread.
				if ( g_shutdown_server )
				{
					if ( !ConfigurationPrompt() )
					{
						break;
					}

					EnterCriticalSection( &console_cs );
					SetConsoleTextAttribute( g_hOutput, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY );
					_wprintf( L"*** Starting Server ***\r\n" );
					SetConsoleTextAttribute( g_hOutput, ConsoleScreenBufferInfo.wAttributes );
					LeaveCriticalSection( &console_cs );

					CloseHandle( server_thread );
					server_thread = ( HANDLE )_CreateThread( NULL, 0, IOCPServer, NULL, 0, NULL );
				}
				else
				{
					if ( console_buffer[ 0 ] == ALPHA_NUM( L'f' ) )
					{
						EnterCriticalSection( &console_cs );
						SetConsoleTextAttribute( g_hOutput, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY );
						_wprintf( L"*** Server Has Already Been Started ***\r\n" );
						SetConsoleTextAttribute( g_hOutput, ConsoleScreenBufferInfo.wAttributes );
						LeaveCriticalSection( &console_cs );
					}
					else
					{
						EnterCriticalSection( &console_cs );
						SetConsoleTextAttribute( g_hOutput, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY );
						_wprintf( L"*** Restarting Server ***\r\n" );
						SetConsoleTextAttribute( g_hOutput, ConsoleScreenBufferInfo.wAttributes );
						LeaveCriticalSection( &console_cs );

						g_restart_server = true;

						_WSASetEvent( g_hCleanupEvent[ 0 ] );
					}
				}
			}
		}
		else if ( console_buffer[ 0 ] == ALPHA_NUM( L'e' ) )
		{
			if ( ws2_32_state == WS2_32_STATE_RUNNING )
			{
				if ( !g_shutdown_server )
				{
					EnterCriticalSection( &console_cs );
					SetConsoleTextAttribute( g_hOutput, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY );
					_wprintf( L"*** Shutting Down Server ***\r\n" );
					SetConsoleTextAttribute( g_hOutput, ConsoleScreenBufferInfo.wAttributes );
					LeaveCriticalSection( &console_cs );

					g_shutdown_server = true;

					_WSASetEvent( g_hCleanupEvent[ 0 ] );
				}
			}
		}
		else if ( console_buffer[ 0 ] == ALPHA_NUM( L'o' ) )
		{
			EnterCriticalSection( &console_cs );
			SetConsoleTextAttribute( g_hOutput, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY );
			_wprintf( ( g_show_output ? L"Output OFF\r\n" : L"Output ON\r\n" ) );
			SetConsoleTextAttribute( g_hOutput, ConsoleScreenBufferInfo.wAttributes );
			LeaveCriticalSection( &console_cs );

			g_show_output = !g_show_output;
		}
		else if ( console_buffer[ 0 ] == ALPHA_NUM( L'i' ) )
		{
			DisplayInfo();
		}
	}
	while ( read > 0 );

	WaitForSingleObject( server_thread, INFINITE );

	CloseHandle( server_thread );

CLEANUP:

	if ( cfg_hostname_ip_address != NULL ) { GlobalFree( cfg_hostname_ip_address ); }
	if ( g_hostname_ip_address != NULL ) { GlobalFree( g_hostname_ip_address ); }
	if ( cfg_hostname_ip_address_s != NULL ){ GlobalFree( cfg_hostname_ip_address_s ); }
	if ( g_hostname_ip_address_s != NULL ) { GlobalFree( g_hostname_ip_address_s ); }

	//

	if ( cfg_forward_hostname_ip_address != NULL ) { GlobalFree( cfg_forward_hostname_ip_address ); }
	if ( g_forward_punycode_hostname_ip_address != NULL ) { GlobalFree( g_forward_punycode_hostname_ip_address ); }
	if ( cfg_forward_hostname_ip_address_s != NULL ) { GlobalFree( cfg_forward_hostname_ip_address_s ); }
	if ( g_forward_punycode_hostname_ip_address_s != NULL ) { GlobalFree( g_forward_punycode_hostname_ip_address_s ); }

	//

	if ( cfg_auth_username != NULL ) { GlobalFree( cfg_auth_username ); }
	if ( cfg_auth_password != NULL ) { GlobalFree( cfg_auth_password ); }
	if ( g_authentication_key != NULL ) { GlobalFree( g_authentication_key ); }
	if ( g_nonce != NULL ) { GlobalFree( g_nonce ); }
	if ( g_opaque != NULL ) { GlobalFree( g_opaque ); }

	//

	if ( cfg_auth_username_s != NULL ) { GlobalFree( cfg_auth_username_s ); }
	if ( cfg_auth_password_s != NULL ) { GlobalFree( cfg_auth_password_s ); }
	if ( g_authentication_key_s != NULL ) { GlobalFree( g_authentication_key_s ); }
	if ( g_nonce_s != NULL ) { GlobalFree( g_nonce_s ); }
	if ( g_opaque_s != NULL ) { GlobalFree( g_opaque_s ); }
	
	//

	if ( cfg_certificate_cer_file_name != NULL ) { GlobalFree( cfg_certificate_cer_file_name ); }
	if ( cfg_certificate_key_file_name != NULL ) { GlobalFree( cfg_certificate_key_file_name ); }
	if ( cfg_certificate_pkcs_file_name != NULL ) { GlobalFree( cfg_certificate_pkcs_file_name ); }
	if ( cfg_certificate_pkcs_password != NULL ) { GlobalFree( cfg_certificate_pkcs_password ); }

	DeleteCriticalSection( &console_cs );

	if ( g_hProvider != NULL )
	{
		_CryptReleaseContext( g_hProvider, 0 );
	}

	// Delay loaded DLLs
	SSL_library_uninit();

	#ifndef WS2_32_USE_STATIC_LIB
		UnInitializeWS2_32();
	#else
		EndWS2_32();
	#endif
	#ifndef RPCRT4_USE_STATIC_LIB
		UnInitializeRpcRt4();
	#endif

UNLOAD_DLLS:

	#ifndef NORMALIZ_USE_STATIC_LIB
		UnInitializeNormaliz();
	#endif
	#ifndef CRYPT32_USE_STATIC_LIB
		UnInitializeCrypt32();
	#endif
	#ifndef SHELL32_USE_STATIC_LIB
		UnInitializeShell32();
	#endif
	#ifndef ADVAPI32_USE_STATIC_LIB
		UnInitializeAdvApi32();
	#endif
	#ifndef NTDLL_USE_STATIC_LIB
		UnInitializeNTDLL();
	#endif

	#ifndef NTDLL_USE_STATIC_LIB
		ExitProcess( 0 );
	#endif

	return 0;
}
