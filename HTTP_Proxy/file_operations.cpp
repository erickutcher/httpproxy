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

#include "globals.h"

#include "file_operations.h"
#include "utilities.h"

#include "connection.h"

char read_config( wchar_t *filename )
{
	char status = 0;

	HANDLE hFile_cfg = CreateFile( filename, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL );
	if ( hFile_cfg != INVALID_HANDLE_VALUE )
	{
		DWORD read = 0, pos = 0;
		DWORD fz = GetFileSize( hFile_cfg, NULL );

		// Our config file is going to be small. If it's something else, we're not going to read it.
		if ( fz >= 33 && fz < 10240 )
		{
			char *cfg_buf = ( char * )GlobalAlloc( GMEM_FIXED, sizeof( char ) * fz + 1 );

			ReadFile( hFile_cfg, cfg_buf, sizeof( char ) * fz, &read, NULL );

			cfg_buf[ fz ] = 0;	// Guarantee a NULL terminated buffer.

			// Read the config. It must be in the order specified below.
			if ( read == fz && _memcmp( cfg_buf, MAGIC_ID_SETTINGS, 4 ) == 0 )
			{
				char *next = cfg_buf + 4;

				_memcpy_s( &cfg_proxy_type, sizeof( unsigned char ), next, sizeof( unsigned char ) );
				next += sizeof( unsigned char );

				_memcpy_s( &cfg_port, sizeof( unsigned short ), next, sizeof( unsigned short ) );
				next += sizeof( unsigned short );

				_memcpy_s( &cfg_require_authentication, sizeof( bool ), next, sizeof( bool ) );
				next += sizeof( bool );

				_memcpy_s( &cfg_auth_type, sizeof( unsigned char ), next, sizeof( unsigned char ) );
				next += sizeof( unsigned char );

				_memcpy_s( &cfg_forward_authentication, sizeof( bool ), next, sizeof( bool ) );
				next += sizeof( bool );

				_memcpy_s( &cfg_forward_connections, sizeof( bool ), next, sizeof( bool ) );
				next += sizeof( bool );

				_memcpy_s( &cfg_forward_port, sizeof( unsigned short ), next, sizeof( unsigned short ) );
				next += sizeof( unsigned short );

				_memcpy_s( &cfg_port_s, sizeof( unsigned short ), next, sizeof( unsigned short ) );
				next += sizeof( unsigned short );

				_memcpy_s( &cfg_require_authentication_s, sizeof( bool ), next, sizeof( bool ) );
				next += sizeof( bool );

				_memcpy_s( &cfg_auth_type_s, sizeof( unsigned char ), next, sizeof( unsigned char ) );
				next += sizeof( unsigned char );

				_memcpy_s( &cfg_forward_authentication_s, sizeof( bool ), next, sizeof( bool ) );
				next += sizeof( bool );

				_memcpy_s( &cfg_forward_connections_s, sizeof( bool ), next, sizeof( bool ) );
				next += sizeof( bool );

				_memcpy_s( &cfg_forward_port_s, sizeof( unsigned short ), next, sizeof( unsigned short ) );
				next += sizeof( unsigned short );

				_memcpy_s( &cfg_use_ssl, sizeof( bool ), next, sizeof( bool ) );
				next += sizeof( bool );

				_memcpy_s( &cfg_protocol, sizeof( unsigned char ), next, sizeof( unsigned char ) );
				next += sizeof( unsigned char );

				_memcpy_s( &cfg_certificate_type, sizeof( unsigned char ), next, sizeof( unsigned char ) );
				next += sizeof( unsigned char );

				_memcpy_s( &cfg_pkcs_password_is_null, sizeof( bool ), next, sizeof( bool ) );
				next += sizeof( bool );

				_memcpy_s( &cfg_decrypt_tunnel, sizeof( bool ), next, sizeof( bool ) );
				next += sizeof( bool );

				_memcpy_s( &cfg_timeout, sizeof( unsigned short ), next, sizeof( unsigned short ) );
				next += sizeof( unsigned short );

				_memcpy_s( &cfg_retry_client_timeout, sizeof( bool ), next, sizeof( bool ) );
				next += sizeof( bool );

				_memcpy_s( &cfg_thread_count, sizeof( unsigned long ), next, sizeof( unsigned long ) );
				next += sizeof( unsigned long );

				int string_length = 0;
				int cfg_val_length = 0;

				if ( ( DWORD )( next - cfg_buf ) < read )
				{
					// Length of the string - not including the NULL character.
					_memcpy_s( &g_auth_username_length, sizeof( unsigned long ), next, sizeof( unsigned short ) );
					next += sizeof( unsigned short );

					if ( g_auth_username_length > 0 )
					{
						if ( ( ( DWORD )( next - cfg_buf ) + g_auth_username_length < read ) )
						{
							// g_auth_username_length does not contain the NULL character of the string.
							cfg_auth_username = ( char * )GlobalAlloc( GMEM_FIXED, sizeof( char ) * ( g_auth_username_length + 1 ) );
							_memcpy_s( cfg_auth_username, g_auth_username_length, next, g_auth_username_length );
							cfg_auth_username[ g_auth_username_length ] = 0; // Sanity;

							decode_cipher( cfg_auth_username, g_auth_username_length );

							next += g_auth_username_length;
						}
						else
						{
							read = 0;
						}
					}
				}

				if ( ( DWORD )( next - cfg_buf ) < read )
				{
					// Length of the string - not including the NULL character.
					_memcpy_s( &g_auth_password_length, sizeof( unsigned long ), next, sizeof( unsigned short ) );
					next += sizeof( unsigned short );

					if ( g_auth_password_length > 0 )
					{
						if ( ( ( DWORD )( next - cfg_buf ) + g_auth_password_length < read ) )
						{
							// g_auth_password_length does not contain the NULL character of the string.
							cfg_auth_password = ( char * )GlobalAlloc( GMEM_FIXED, sizeof( char ) * ( g_auth_password_length + 1 ) );
							_memcpy_s( cfg_auth_password, g_auth_password_length, next, g_auth_password_length );
							cfg_auth_password[ g_auth_password_length ] = 0; // Sanity;

							decode_cipher( cfg_auth_password, g_auth_password_length );

							next += g_auth_password_length;
						}
						else
						{
							read = 0;
						}
					}
				}

				if ( ( DWORD )( next - cfg_buf ) < read )
				{
					// Length of the string - not including the NULL character.
					_memcpy_s( &g_auth_username_length_s, sizeof( unsigned long ), next, sizeof( unsigned short ) );
					next += sizeof( unsigned short );

					if ( g_auth_username_length_s > 0 )
					{
						if ( ( ( DWORD )( next - cfg_buf ) + g_auth_username_length_s < read ) )
						{
							// g_auth_username_length_s does not contain the NULL character of the string.
							cfg_auth_username_s = ( char * )GlobalAlloc( GMEM_FIXED, sizeof( char ) * ( g_auth_username_length_s + 1 ) );
							_memcpy_s( cfg_auth_username_s, g_auth_username_length_s, next, g_auth_username_length_s );
							cfg_auth_username_s[ g_auth_username_length_s ] = 0; // Sanity;

							decode_cipher( cfg_auth_username_s, g_auth_username_length_s );

							next += g_auth_username_length_s;
						}
						else
						{
							read = 0;
						}
					}
				}

				if ( ( DWORD )( next - cfg_buf ) < read )
				{
					// Length of the string - not including the NULL character.
					_memcpy_s( &g_auth_password_length_s, sizeof( unsigned long ), next, sizeof( unsigned short ) );
					next += sizeof( unsigned short );

					if ( g_auth_password_length_s > 0 )
					{
						if ( ( ( DWORD )( next - cfg_buf ) + g_auth_password_length_s < read ) )
						{
							// g_auth_password_length_s does not contain the NULL character of the string.
							cfg_auth_password_s = ( char * )GlobalAlloc( GMEM_FIXED, sizeof( char ) * ( g_auth_password_length_s + 1 ) );
							_memcpy_s( cfg_auth_password_s, g_auth_password_length_s, next, g_auth_password_length_s );
							cfg_auth_password_s[ g_auth_password_length_s ] = 0; // Sanity;

							decode_cipher( cfg_auth_password_s, g_auth_password_length_s );

							next += g_auth_password_length_s;
						}
						else
						{
							read = 0;
						}
					}
				}

				if ( ( DWORD )( next - cfg_buf ) < read )
				{
					// Length of the string - not including the NULL character.
					_memcpy_s( &string_length, sizeof( unsigned short ), next, sizeof( unsigned short ) );
					next += sizeof( unsigned short );

					if ( string_length > 0 )
					{
						if ( ( ( DWORD )( next - cfg_buf ) + string_length < read ) )
						{
							// string_length does not contain the NULL character of the string.
							char *certificate_password = ( char * )GlobalAlloc( GMEM_FIXED, sizeof( char ) * ( string_length + 1 ) );
							_memcpy_s( certificate_password, string_length, next, string_length );
							certificate_password[ string_length ] = 0; // Sanity;

							decode_cipher( certificate_password, string_length );

							// Read password.
							cfg_val_length = MultiByteToWideChar( CP_UTF8, 0, certificate_password, string_length + 1, NULL, 0 );	// Include the NULL character.
							cfg_certificate_pkcs_password = ( wchar_t * )GlobalAlloc( GMEM_FIXED, sizeof( wchar_t ) * cfg_val_length );
							MultiByteToWideChar( CP_UTF8, 0, certificate_password, string_length + 1, cfg_certificate_pkcs_password, cfg_val_length );

							GlobalFree( certificate_password );

							next += string_length;
						}
						else
						{
							read = 0;
						}
					}
					else if ( !cfg_pkcs_password_is_null )
					{
						// If the length is 0 and the password was not saved as a NULL password, then use the empty string as the password.
						cfg_certificate_pkcs_password = ( wchar_t * )GlobalAlloc( GPTR, sizeof( wchar_t ) );
						cfg_certificate_pkcs_password[ 0 ] = 0;	// Sanity.
					}
				}

				if ( ( DWORD )( next - cfg_buf ) < read )
				{
					string_length = lstrlenA( next ) + 1;

					cfg_val_length = MultiByteToWideChar( CP_UTF8, 0, next, string_length, NULL, 0 );	// Include the NULL terminator.
					cfg_certificate_pkcs_file_name = ( wchar_t * )GlobalAlloc( GMEM_FIXED, sizeof( wchar_t ) * cfg_val_length );
					MultiByteToWideChar( CP_UTF8, 0, next, string_length, cfg_certificate_pkcs_file_name, cfg_val_length );

					next += string_length;
				}

				if ( ( DWORD )( next - cfg_buf ) < read )
				{
					string_length = lstrlenA( next ) + 1;

					cfg_val_length = MultiByteToWideChar( CP_UTF8, 0, next, string_length, NULL, 0 );	// Include the NULL terminator.
					cfg_certificate_cer_file_name = ( wchar_t * )GlobalAlloc( GMEM_FIXED, sizeof( wchar_t ) * cfg_val_length );
					MultiByteToWideChar( CP_UTF8, 0, next, string_length, cfg_certificate_cer_file_name, cfg_val_length );

					next += string_length;
				}

				if ( ( DWORD )( next - cfg_buf ) < read )
				{
					string_length = lstrlenA( next ) + 1;

					cfg_val_length = MultiByteToWideChar( CP_UTF8, 0, next, string_length, NULL, 0 );	// Include the NULL terminator.
					cfg_certificate_key_file_name = ( wchar_t * )GlobalAlloc( GMEM_FIXED, sizeof( wchar_t ) * cfg_val_length );
					MultiByteToWideChar( CP_UTF8, 0, next, string_length, cfg_certificate_key_file_name, cfg_val_length );

					next += string_length;
				}

				if ( ( DWORD )( next - cfg_buf ) < read )
				{
					string_length = lstrlenA( next ) + 1;

					cfg_val_length = MultiByteToWideChar( CP_UTF8, 0, next, string_length, NULL, 0 );	// Include the NULL terminator.
					cfg_hostname_ip_address = ( wchar_t * )GlobalAlloc( GMEM_FIXED, sizeof( wchar_t ) * cfg_val_length );
					MultiByteToWideChar( CP_UTF8, 0, next, string_length, cfg_hostname_ip_address, cfg_val_length );

					next += string_length;
				}

				if ( ( DWORD )( next - cfg_buf ) < read )
				{
					string_length = lstrlenA( next ) + 1;

					cfg_val_length = MultiByteToWideChar( CP_UTF8, 0, next, string_length, NULL, 0 );	// Include the NULL terminator.
					cfg_forward_hostname_ip_address = ( wchar_t * )GlobalAlloc( GMEM_FIXED, sizeof( wchar_t ) * cfg_val_length );
					MultiByteToWideChar( CP_UTF8, 0, next, string_length, cfg_forward_hostname_ip_address, cfg_val_length );

					next += string_length;
				}

				if ( ( DWORD )( next - cfg_buf ) < read )
				{
					string_length = lstrlenA( next ) + 1;

					cfg_val_length = MultiByteToWideChar( CP_UTF8, 0, next, string_length, NULL, 0 );	// Include the NULL terminator.
					cfg_hostname_ip_address_s = ( wchar_t * )GlobalAlloc( GMEM_FIXED, sizeof( wchar_t ) * cfg_val_length );
					MultiByteToWideChar( CP_UTF8, 0, next, string_length, cfg_hostname_ip_address_s, cfg_val_length );

					next += string_length;
				}	

				if ( ( DWORD )( next - cfg_buf ) < read )
				{
					string_length = lstrlenA( next ) + 1;

					cfg_val_length = MultiByteToWideChar( CP_UTF8, 0, next, string_length, NULL, 0 );	// Include the NULL terminator.
					cfg_forward_hostname_ip_address_s = ( wchar_t * )GlobalAlloc( GMEM_FIXED, sizeof( wchar_t ) * cfg_val_length );
					MultiByteToWideChar( CP_UTF8, 0, next, string_length, cfg_forward_hostname_ip_address_s, cfg_val_length );

					next += string_length;
				}

				// Set the default values for bad configuration values.

				if ( cfg_port == 0 ) { cfg_port = 1; }
				if ( cfg_port_s == 0 ) { cfg_port_s = 1; }

				if ( cfg_forward_port == 0 ) { cfg_forward_port = 1; }
				if ( cfg_forward_port_s == 0 ) { cfg_forward_port_s = 1; }

				if ( cfg_timeout > 300 || cfg_timeout < 1 ) { cfg_timeout = 30; }

				if ( cfg_thread_count > g_max_threads )
				{
					cfg_thread_count = max( ( g_max_threads / 2 ), 1 );
				}
				else if ( cfg_thread_count == 0 )
				{
					cfg_thread_count = 1;
				}

				if ( cfg_protocol > 4 ) { cfg_protocol = 4; }	// TLS 1.2.
			}
			else
			{
				status = -2;	// Bad file format.
			}

			GlobalFree( cfg_buf );
		}
		else
		{
			status = -3;	// Incorrect file size.
		}

		CloseHandle( hFile_cfg );
	}
	else
	{
		status = -1;	// Can't open file for reading.
	}

	if ( cfg_hostname_ip_address == NULL )
	{
		cfg_hostname_ip_address = ( wchar_t * )GlobalAlloc( GMEM_FIXED, sizeof( wchar_t ) * 10 );
		_wmemcpy_s( cfg_hostname_ip_address, 10, L"localhost\0", 10 );
		cfg_hostname_ip_address[ 9 ] = 0;	// Sanity.
	}

	if ( cfg_forward_hostname_ip_address == NULL )
	{
		cfg_forward_hostname_ip_address = ( wchar_t * )GlobalAlloc( GMEM_FIXED, sizeof( wchar_t ) * 10 );
		_wmemcpy_s( cfg_forward_hostname_ip_address, 10, L"localhost\0", 10 );
		cfg_forward_hostname_ip_address[ 9 ] = 0;	// Sanity.
	}

	if ( cfg_hostname_ip_address_s == NULL )
	{
		cfg_hostname_ip_address_s = ( wchar_t * )GlobalAlloc( GMEM_FIXED, sizeof( wchar_t ) * 10 );
		_wmemcpy_s( cfg_hostname_ip_address_s, 10, L"localhost\0", 10 );
		cfg_hostname_ip_address_s[ 9 ] = 0;	// Sanity.
	}

	if ( cfg_forward_hostname_ip_address_s == NULL )
	{
		cfg_forward_hostname_ip_address_s = ( wchar_t * )GlobalAlloc( GMEM_FIXED, sizeof( wchar_t ) * 10 );
		_wmemcpy_s( cfg_forward_hostname_ip_address_s, 10, L"localhost\0", 10 );
		cfg_forward_hostname_ip_address_s[ 9 ] = 0;	// Sanity.
	}

	return status;
}

char save_config( wchar_t *filename )
{
	char status = 0;

	HANDLE hFile_cfg = CreateFile( filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL );
	if ( hFile_cfg != INVALID_HANDLE_VALUE )
	{
		int size = ( sizeof( unsigned short ) * 5 ) + ( sizeof( char ) * 9 ) + ( sizeof( bool ) * 10 ) + ( sizeof( unsigned long ) * 1 );
		int pos = 0;

		char *write_buf = ( char * )GlobalAlloc( GMEM_FIXED, sizeof( char ) * size );

		_memcpy_s( write_buf + pos, size - pos, MAGIC_ID_SETTINGS, sizeof( char ) * 4 );	// Magic identifier for the main program's settings.
		pos += ( sizeof( char ) * 4 );

		_memcpy_s( write_buf + pos, size - pos, &cfg_proxy_type, sizeof( unsigned char ) );
		pos += sizeof( unsigned char );

		_memcpy_s( write_buf + pos, size - pos, &cfg_port, sizeof( unsigned short ) );
		pos += sizeof( unsigned short );

		_memcpy_s( write_buf + pos, size - pos, &cfg_require_authentication, sizeof( bool ) );
		pos += sizeof( bool );

		_memcpy_s( write_buf + pos, size - pos, &cfg_auth_type, sizeof( unsigned char ) );
		pos += sizeof( unsigned char );

		_memcpy_s( write_buf + pos, size - pos, &cfg_forward_authentication, sizeof( bool ) );
		pos += sizeof( bool );

		_memcpy_s( write_buf + pos, size - pos, &cfg_forward_connections, sizeof( bool ) );
		pos += sizeof( bool );

		_memcpy_s( write_buf + pos, size - pos, &cfg_forward_port, sizeof( unsigned short ) );
		pos += sizeof( unsigned short );

		_memcpy_s( write_buf + pos, size - pos, &cfg_port_s, sizeof( unsigned short ) );
		pos += sizeof( unsigned short );

		_memcpy_s( write_buf + pos, size - pos, &cfg_require_authentication_s, sizeof( bool ) );
		pos += sizeof( bool );

		_memcpy_s( write_buf + pos, size - pos, &cfg_auth_type_s, sizeof( unsigned char ) );
		pos += sizeof( unsigned char );

		_memcpy_s( write_buf + pos, size - pos, &cfg_forward_authentication_s, sizeof( bool ) );
		pos += sizeof( bool );

		_memcpy_s( write_buf + pos, size - pos, &cfg_forward_connections_s, sizeof( bool ) );
		pos += sizeof( bool );

		_memcpy_s( write_buf + pos, size - pos, &cfg_forward_port_s, sizeof( unsigned short ) );
		pos += sizeof( unsigned short );

		_memcpy_s( write_buf + pos, size - pos, &cfg_use_ssl, sizeof( bool ) );
		pos += sizeof( bool );

		_memcpy_s( write_buf + pos, size - pos, &cfg_protocol, sizeof( unsigned char ) );
		pos += sizeof( unsigned char );

		_memcpy_s( write_buf + pos, size - pos, &cfg_certificate_type, sizeof( unsigned char ) );
		pos += sizeof( unsigned char );

		_memcpy_s( write_buf + pos, size - pos, &cfg_pkcs_password_is_null, sizeof( bool ) );
		pos += sizeof( bool );

		_memcpy_s( write_buf + pos, size - pos, &cfg_decrypt_tunnel, sizeof( bool ) );
		pos += sizeof( bool );

		_memcpy_s( write_buf + pos, size - pos, &cfg_timeout, sizeof( unsigned short ) );
		pos += sizeof( unsigned short );

		_memcpy_s( write_buf + pos, size - pos, &cfg_retry_client_timeout, sizeof( bool ) );
		pos += sizeof( bool );

		_memcpy_s( write_buf + pos, size - pos, &cfg_thread_count, sizeof( unsigned long ) );
		//pos += sizeof( unsigned long );

		DWORD write = 0;
		WriteFile( hFile_cfg, write_buf, size, &write, NULL );

		GlobalFree( write_buf );

		int cfg_val_length = 0;
		char *utf8_cfg_val = NULL;

		if ( cfg_auth_username != NULL )
		{
			cfg_val_length = ( sizeof( char ) * ( g_auth_username_length + 1 ) ) + sizeof( unsigned short ); // Add 2 bytes for our encoded length.
			utf8_cfg_val = ( char * )GlobalAlloc( GMEM_FIXED, sizeof( char ) * cfg_val_length ); // Size includes the null character.

			_memcpy_s( utf8_cfg_val, cfg_val_length, &g_auth_username_length, sizeof( unsigned short ) );
			_memcpy_s( utf8_cfg_val + sizeof( unsigned short ), cfg_val_length - sizeof( unsigned short ), cfg_auth_username, g_auth_username_length + 1 );

			encode_cipher( utf8_cfg_val + sizeof( unsigned short ), g_auth_username_length );

			WriteFile( hFile_cfg, utf8_cfg_val, g_auth_username_length + sizeof( unsigned short ), &write, NULL );	// Do not write the NULL terminator.

			GlobalFree( utf8_cfg_val );
		}
		else
		{
			WriteFile( hFile_cfg, "\0\0", 2, &write, NULL );
		}

		if ( cfg_auth_password != NULL )
		{
			cfg_val_length = ( sizeof( char ) * ( g_auth_password_length + 1 ) ) + sizeof( unsigned short ); // Add 2 bytes for our encoded length.
			utf8_cfg_val = ( char * )GlobalAlloc( GMEM_FIXED, sizeof( char ) * cfg_val_length ); // Size includes the null character.

			_memcpy_s( utf8_cfg_val, cfg_val_length, &g_auth_password_length, sizeof( unsigned short ) );
			_memcpy_s( utf8_cfg_val + sizeof( unsigned short ), cfg_val_length - sizeof( unsigned short ), cfg_auth_password, g_auth_password_length + 1 );

			encode_cipher( utf8_cfg_val + sizeof( unsigned short ), g_auth_password_length );

			WriteFile( hFile_cfg, utf8_cfg_val, g_auth_password_length + sizeof( unsigned short ), &write, NULL );	// Do not write the NULL terminator.

			GlobalFree( utf8_cfg_val );
		}
		else
		{
			WriteFile( hFile_cfg, "\0\0", 2, &write, NULL );
		}

		if ( cfg_auth_username_s != NULL )
		{
			cfg_val_length = ( sizeof( char ) * ( g_auth_username_length_s + 1 ) ) + sizeof( unsigned short ); // Add 2 bytes for our encoded length.
			utf8_cfg_val = ( char * )GlobalAlloc( GMEM_FIXED, sizeof( char ) * cfg_val_length ); // Size includes the null character.

			_memcpy_s( utf8_cfg_val, cfg_val_length, &g_auth_username_length_s, sizeof( unsigned short ) );
			_memcpy_s( utf8_cfg_val + sizeof( unsigned short ), cfg_val_length - sizeof( unsigned short ), cfg_auth_username_s, g_auth_username_length_s + 1 );

			encode_cipher( utf8_cfg_val + sizeof( unsigned short ), g_auth_username_length_s );

			WriteFile( hFile_cfg, utf8_cfg_val, g_auth_username_length_s + sizeof( unsigned short ), &write, NULL );	// Do not write the NULL terminator.

			GlobalFree( utf8_cfg_val );
		}
		else
		{
			WriteFile( hFile_cfg, "\0\0", 2, &write, NULL );
		}

		if ( cfg_auth_password_s != NULL )
		{
			cfg_val_length = ( sizeof( char ) * ( g_auth_password_length_s + 1 ) ) + sizeof( unsigned short ); // Add 2 bytes for our encoded length.
			utf8_cfg_val = ( char * )GlobalAlloc( GMEM_FIXED, sizeof( char ) * cfg_val_length ); // Size includes the null character.

			_memcpy_s( utf8_cfg_val, cfg_val_length, &g_auth_password_length_s, sizeof( unsigned short ) );
			_memcpy_s( utf8_cfg_val + sizeof( unsigned short ), cfg_val_length - sizeof( unsigned short ), cfg_auth_password_s, g_auth_password_length_s + 1 );

			encode_cipher( utf8_cfg_val + sizeof( unsigned short ), g_auth_password_length_s );

			WriteFile( hFile_cfg, utf8_cfg_val, g_auth_password_length_s + sizeof( unsigned short ), &write, NULL );	// Do not write the NULL terminator.

			GlobalFree( utf8_cfg_val );
		}
		else
		{
			WriteFile( hFile_cfg, "\0\0", 2, &write, NULL );
		}

		if ( cfg_certificate_pkcs_password != NULL )
		{
			cfg_val_length = WideCharToMultiByte( CP_UTF8, 0, cfg_certificate_pkcs_password, -1, NULL, 0, NULL, NULL ) + sizeof( unsigned short );	// Add 2 bytes for our encoded length.
			utf8_cfg_val = ( char * )GlobalAlloc( GMEM_FIXED, sizeof( char ) * cfg_val_length ); // Size includes the null character.
			cfg_val_length = WideCharToMultiByte( CP_UTF8, 0, cfg_certificate_pkcs_password, -1, utf8_cfg_val + sizeof( unsigned short ), cfg_val_length - sizeof( unsigned short ), NULL, NULL );

			int length = cfg_val_length - 1;	// Exclude the NULL terminator.
			_memcpy_s( utf8_cfg_val, cfg_val_length, &length, sizeof( unsigned short ) );

			encode_cipher( utf8_cfg_val + sizeof( unsigned short ), length );

			WriteFile( hFile_cfg, utf8_cfg_val, length + sizeof( unsigned short ), &write, NULL );	// Do not write the NULL terminator.

			GlobalFree( utf8_cfg_val );
		}
		else
		{
			WriteFile( hFile_cfg, "\0\0", 2, &write, NULL );
		}

		if ( cfg_certificate_pkcs_file_name != NULL )
		{
			cfg_val_length = WideCharToMultiByte( CP_UTF8, 0, cfg_certificate_pkcs_file_name, -1, NULL, 0, NULL, NULL );
			utf8_cfg_val = ( char * )GlobalAlloc( GMEM_FIXED, sizeof( char ) * cfg_val_length ); // Size includes the null character.
			cfg_val_length = WideCharToMultiByte( CP_UTF8, 0, cfg_certificate_pkcs_file_name, -1, utf8_cfg_val, cfg_val_length, NULL, NULL );

			WriteFile( hFile_cfg, utf8_cfg_val, cfg_val_length, &write, NULL );

			GlobalFree( utf8_cfg_val );
		}
		else
		{
			WriteFile( hFile_cfg, "\0", 1, &write, NULL );
		}

		if ( cfg_certificate_cer_file_name != NULL )
		{
			cfg_val_length = WideCharToMultiByte( CP_UTF8, 0, cfg_certificate_cer_file_name, -1, NULL, 0, NULL, NULL );
			utf8_cfg_val = ( char * )GlobalAlloc( GMEM_FIXED, sizeof( char ) * cfg_val_length ); // Size includes the null character.
			cfg_val_length = WideCharToMultiByte( CP_UTF8, 0, cfg_certificate_cer_file_name, -1, utf8_cfg_val, cfg_val_length, NULL, NULL );

			WriteFile( hFile_cfg, utf8_cfg_val, cfg_val_length, &write, NULL );

			GlobalFree( utf8_cfg_val );
		}
		else
		{
			WriteFile( hFile_cfg, "\0", 1, &write, NULL );
		}

		if ( cfg_certificate_key_file_name != NULL )
		{
			cfg_val_length = WideCharToMultiByte( CP_UTF8, 0, cfg_certificate_key_file_name, -1, NULL, 0, NULL, NULL );
			utf8_cfg_val = ( char * )GlobalAlloc( GMEM_FIXED, sizeof( char ) * cfg_val_length ); // Size includes the null character.
			cfg_val_length = WideCharToMultiByte( CP_UTF8, 0, cfg_certificate_key_file_name, -1, utf8_cfg_val, cfg_val_length, NULL, NULL );

			WriteFile( hFile_cfg, utf8_cfg_val, cfg_val_length, &write, NULL );

			GlobalFree( utf8_cfg_val );
		}
		else
		{
			WriteFile( hFile_cfg, "\0", 1, &write, NULL );
		}

		if ( cfg_hostname_ip_address != NULL )
		{
			cfg_val_length = WideCharToMultiByte( CP_UTF8, 0, cfg_hostname_ip_address, -1, NULL, 0, NULL, NULL );
			utf8_cfg_val = ( char * )GlobalAlloc( GMEM_FIXED, sizeof( char ) * cfg_val_length ); // Size includes the null character.
			cfg_val_length = WideCharToMultiByte( CP_UTF8, 0, cfg_hostname_ip_address, -1, utf8_cfg_val, cfg_val_length, NULL, NULL );

			WriteFile( hFile_cfg, utf8_cfg_val, cfg_val_length, &write, NULL );

			GlobalFree( utf8_cfg_val );
		}
		else
		{
			WriteFile( hFile_cfg, "\0", 1, &write, NULL );
		}

		if ( cfg_forward_hostname_ip_address != NULL )
		{
			cfg_val_length = WideCharToMultiByte( CP_UTF8, 0, cfg_forward_hostname_ip_address, -1, NULL, 0, NULL, NULL );
			utf8_cfg_val = ( char * )GlobalAlloc( GMEM_FIXED, sizeof( char ) * cfg_val_length ); // Size includes the null character.
			cfg_val_length = WideCharToMultiByte( CP_UTF8, 0, cfg_forward_hostname_ip_address, -1, utf8_cfg_val, cfg_val_length, NULL, NULL );

			WriteFile( hFile_cfg, utf8_cfg_val, cfg_val_length, &write, NULL );

			GlobalFree( utf8_cfg_val );
		}
		else
		{
			WriteFile( hFile_cfg, "\0", 1, &write, NULL );
		}

		if ( cfg_hostname_ip_address_s != NULL )
		{
			cfg_val_length = WideCharToMultiByte( CP_UTF8, 0, cfg_hostname_ip_address_s, -1, NULL, 0, NULL, NULL );
			utf8_cfg_val = ( char * )GlobalAlloc( GMEM_FIXED, sizeof( char ) * cfg_val_length ); // Size includes the null character.
			cfg_val_length = WideCharToMultiByte( CP_UTF8, 0, cfg_hostname_ip_address_s, -1, utf8_cfg_val, cfg_val_length, NULL, NULL );

			WriteFile( hFile_cfg, utf8_cfg_val, cfg_val_length, &write, NULL );

			GlobalFree( utf8_cfg_val );
		}
		else
		{
			WriteFile( hFile_cfg, "\0", 1, &write, NULL );
		}

		if ( cfg_forward_hostname_ip_address_s != NULL )
		{
			cfg_val_length = WideCharToMultiByte( CP_UTF8, 0, cfg_forward_hostname_ip_address_s, -1, NULL, 0, NULL, NULL );
			utf8_cfg_val = ( char * )GlobalAlloc( GMEM_FIXED, sizeof( char ) * cfg_val_length ); // Size includes the null character.
			cfg_val_length = WideCharToMultiByte( CP_UTF8, 0, cfg_forward_hostname_ip_address_s, -1, utf8_cfg_val, cfg_val_length, NULL, NULL );

			WriteFile( hFile_cfg, utf8_cfg_val, cfg_val_length, &write, NULL );

			GlobalFree( utf8_cfg_val );
		}
		else
		{
			WriteFile( hFile_cfg, "\0", 1, &write, NULL );
		}

		CloseHandle( hFile_cfg );
	}
	else
	{
		status = -1;	// Can't open file for writing.
	}

	return status;
}
