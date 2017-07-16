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

#include "http.h"
#include "lite_shell32.h"
#include "lite_advapi32.h"
#include "utilities.h"
#include <limits.h>


// This basically skips past an expression string when searching for a particular character.
// end is set if the end of the string is reached and the character is not found.
char *FindCharExcludeExpression( char *start, char **end, char character )
{
	unsigned char opened_quote = 0;

	char *pos = start;

	while ( pos != NULL )
	{
		// If an end was supplied, then search until we reach it. If not, then search until we reach the NULL terminator.
		if ( ( *end != NULL && pos < *end ) || ( *end == NULL && *pos != NULL ) )
		{
			if ( opened_quote == 0 )
			{
				// Exit if we've found the end of the value.
				if ( *pos == character )
				{
					break;
				}
				else if ( *pos == '\'' || *pos == '\"' )	// A single or double quote has been opened.
				{
					opened_quote = *pos;
				}
			}
			else	// Find the single or double quote's pair (closing quote).
			{
				if ( *pos == opened_quote || *pos == opened_quote )
				{
					opened_quote = 0;
				}
			}

			++pos;
		}
		else
		{
			// Make sure there's no open quote if we've reached the end.
			if ( *end == NULL && opened_quote == 0 )
			{
				*end = pos;
			}

			pos = NULL;
		}
	}

	return pos;
}

char *GetHeaderValue( char *header, char *field_name, unsigned long field_name_length, char **value_start, char **value_end )
{
	char *field_name_start = NULL;
	char *field_end = NULL;
	char *itr_field = header;

	while ( true )
	{
		// Find the end of the field.
		field_end = _StrStrA( itr_field, "\r\n" );
		if ( field_end != NULL && ( field_end != itr_field ) )	// Ensures we don't go past the last "\r\n".
		{
			// Skip whitespace that might appear before the field name.
			while ( *itr_field == ' ' || *itr_field == '\t' || *itr_field == '\f' )
			{
				++itr_field;
			}

			field_name_start = itr_field;

			while ( true )
			{
				// Find the end of the field name.
				if ( itr_field < field_end )
				{
					// The field name will end with a colon.
					if ( *itr_field == ':' )
					{
						// We found the field name.
						if ( ( itr_field - field_name_start ) == field_name_length &&
							 ( _StrCmpNIA( field_name_start, field_name, field_name_length ) == 0 ) )
						{
							++itr_field;

							// Skip whitespace that might appear before the field value.
							while ( *itr_field == ' ' || *itr_field == '\t' || *itr_field == '\f' )
							{
								++itr_field;
							}

							// Skip whitespace that could appear before the "\r\n", but after the field value.
							while ( ( field_end - 1 ) >= itr_field )
							{
								if ( *( field_end - 1 ) != ' ' && *( field_end - 1 ) != '\t' && *( field_end - 1 ) != '\f' )
								{
									break;
								}

								--field_end;
							}

							*value_start = itr_field;
							*value_end = field_end;

							return field_name_start;
						}
						else	// Bad/wrong field name. Move to the next field.
						{
							itr_field = field_end + 2;

							break;
						}
					}

					++itr_field;
				}
				else	// Bad/wrong field name. Move to the next field.
				{
					itr_field = field_end + 2;

					break;
				}
			}
		}
		else	// A complete field end was not found, or we reached the end of the header.
		{
			break;
		}
	}

	return NULL;
}

char *GetDigestValue( char *digest_value, char *digest_value_name, unsigned long digest_value_name_length, char **value_start, char **value_end )
{
	char *digest_value_name_start = NULL;
	char *digest_value_end = NULL;
	char *itr_digest_value = digest_value;

	char *digest_end = NULL;

	while ( true )
	{
		// Find the end of the digest value.
		// If the second parameter is NULL, then it'll be set to the end of the string and FindCharExcludeExpression will return NULL.
		digest_value_end = FindCharExcludeExpression( itr_digest_value, &digest_end, ',' );

		if ( digest_value_end == NULL && digest_end != NULL )
		{
			digest_value_end = digest_end;
		}

		if ( digest_value_end != NULL && ( digest_value_end != itr_digest_value ) )	// Ensures we don't go past the last digest value.
		{
			// Skip whitespace that might appear before the field name.
			while ( *itr_digest_value == ' ' || *itr_digest_value == '\t' || *itr_digest_value == '\f' )
			{
				++itr_digest_value;
			}

			digest_value_name_start = itr_digest_value;

			while ( true )
			{
				// Find the end of the diget value name.
				if ( itr_digest_value < digest_value_end )
				{
					// The digest value name will end with a equals.
					if ( *itr_digest_value == '=' )
					{
						// We found the digest value name.
						if ( ( itr_digest_value - digest_value_name_start ) == digest_value_name_length &&
							 ( _StrCmpNIA( digest_value_name_start, digest_value_name, digest_value_name_length ) == 0 ) )
						{
							++itr_digest_value;

							// Skip whitespace that might appear before the digest value.
							while ( *itr_digest_value == ' ' || *itr_digest_value == '\t' || *itr_digest_value == '\f' )
							{
								++itr_digest_value;
							}

							// Skip whitespace that could appear before the ",", but after the digest value.
							while ( ( digest_value_end - 1 ) >= itr_digest_value )
							{
								if ( *( digest_value_end - 1 ) != ' ' && *( digest_value_end - 1 ) != '\t' && *( digest_value_end - 1 ) != '\f' )
								{
									break;
								}

								--digest_value_end;
							}

							*value_start = itr_digest_value;
							*value_end = digest_value_end;

							return digest_value_name_start;
						}
						else	// Bad/wrong digest value name. Move to the next digest value.
						{
							if ( digest_end != NULL )
							{
								return NULL;
							}
							else
							{
								itr_digest_value = digest_value_end + 1;

								break;
							}
						}
					}

					++itr_digest_value;
				}
				else	// Bad/wrong digest value name. Move to the next digest value.
				{
					if ( digest_end != NULL )
					{
						return NULL;
					}
					else
					{
						itr_digest_value = digest_value_end + 1;

						break;
					}
				}
			}
		}
		else	// A complete digest value end was not found, or we reached the end of the digest.
		{
			break;
		}
	}

	return NULL;
}



unsigned char GetAuthenticate( char *header, AUTH_INFO *auth_info )
{
	char *authenticate_header = NULL;
	char *authenticate_header_end = NULL;

	auth_info->auth_start = GetHeaderValue( header, "Proxy-Authorization", 19, &authenticate_header, &authenticate_header_end );
	if ( auth_info->auth_start != NULL )
	{
		auth_info->auth_end = authenticate_header_end;

		if (  _StrStrIA( authenticate_header, "Basic " ) != NULL )	// The protocol doesn't specify whether "Basic" is case-sensitive or not. Note that the protocol requires a single space (SP) after "Basic".
		{
			char *basic_value_start = authenticate_header + 6;

			char *basic_value_end = _StrStrA( basic_value_start, "\r\n" );
			if ( basic_value_end != NULL )
			{
				auth_info->basic_encode = basic_value_start;
				auth_info->basic_encode_end = basic_value_end;
			}

			return AUTH_TYPE_BASIC;
		}
		else if (  _StrStrIA( authenticate_header, "Digest " ) != NULL )	// The protocol doesn't specify whether "Digest" is case-sensitive or not. Note that the protocol requires a single space (SP) after "Digest".
		{
			char tmp_end = *authenticate_header_end;
			*authenticate_header_end = 0;	// Sanity

			authenticate_header += 7;

			char *digest_value = NULL;
			char *digest_value_end = NULL;

			if ( GetDigestValue( authenticate_header, "username", 8, &digest_value, &digest_value_end ) != NULL )
			{
				char delimiter = digest_value[ 0 ];
				if ( delimiter == '\"' || delimiter == '\'' )
				{
					++digest_value;

					if ( *( digest_value_end - 1 ) == delimiter )
					{
						--digest_value_end;
					}
				}

				auth_info->username = digest_value;
				auth_info->username_end = digest_value_end;
			}

			if ( GetDigestValue( authenticate_header, "realm", 5, &digest_value, &digest_value_end ) != NULL )
			{
				char delimiter = digest_value[ 0 ];
				if ( delimiter == '\"' || delimiter == '\'' )
				{
					++digest_value;

					if ( *( digest_value_end - 1 ) == delimiter )
					{
						--digest_value_end;
					}
				}

				auth_info->realm = digest_value;
				auth_info->realm_end = digest_value_end;
			}

			if ( GetDigestValue( authenticate_header, "nonce", 5, &digest_value, &digest_value_end ) != NULL )
			{
				char delimiter = digest_value[ 0 ];
				if ( delimiter == '\"' || delimiter == '\'' )
				{
					++digest_value;

					if ( *( digest_value_end - 1 ) == delimiter )
					{
						--digest_value_end;
					}
				}

				auth_info->nonce = digest_value;
				auth_info->nonce_end = digest_value_end;
			}

			if ( GetDigestValue( authenticate_header, "algorithm", 9, &digest_value, &digest_value_end ) != NULL )
			{
				char delimiter = digest_value[ 0 ];
				if ( delimiter == '\"' || delimiter == '\'' )
				{
					++digest_value;

					if ( *( digest_value_end - 1 ) == delimiter )
					{
						--digest_value_end;
					}
				}

				if ( ( digest_value_end - digest_value ) == 8 && _StrCmpNIA( digest_value, "MD5-sess", 8 ) == 0 )
				{
					auth_info->algorithm = 2;
				}
				else if ( ( digest_value_end - digest_value ) == 3 && _StrCmpNIA( digest_value, "MD5", 3 ) == 0 )
				{
					auth_info->algorithm = 1;
				}
				else
				{
					auth_info->algorithm = 3;	// Unhandled.
				}
			}

			if ( GetDigestValue( authenticate_header, "uri", 3, &digest_value, &digest_value_end ) != NULL )
			{
				char delimiter = digest_value[ 0 ];
				if ( delimiter == '\"' || delimiter == '\'' )
				{
					++digest_value;

					if ( *( digest_value_end - 1 ) == delimiter )
					{
						--digest_value_end;
					}
				}

				auth_info->uri = digest_value;
				auth_info->uri_end = digest_value_end;
			}

			if ( GetDigestValue( authenticate_header, "response", 8, &digest_value, &digest_value_end ) != NULL )
			{
				char delimiter = digest_value[ 0 ];
				if ( delimiter == '\"' || delimiter == '\'' )
				{
					++digest_value;

					if ( *( digest_value_end - 1 ) == delimiter )
					{
						--digest_value_end;
					}
				}

				auth_info->response = digest_value;
				auth_info->response_end = digest_value_end;
			}

			if ( GetDigestValue( authenticate_header, "opaque", 6, &digest_value, &digest_value_end ) != NULL )
			{
				char delimiter = digest_value[ 0 ];
				if ( delimiter == '\"' || delimiter == '\'' )
				{
					++digest_value;

					if ( *( digest_value_end - 1 ) == delimiter )
					{
						--digest_value_end;
					}
				}

				auth_info->opaque = digest_value;
				auth_info->opaque_end = digest_value_end;
			}

			if ( GetDigestValue( authenticate_header, "qop", 3, &digest_value, &digest_value_end ) != NULL )
			{
				char delimiter = digest_value[ 0 ];
				if ( delimiter == '\"' || delimiter == '\'' )
				{
					++digest_value;

					if ( *( digest_value_end - 1 ) == delimiter )
					{
						--digest_value_end;
					}
				}

				auth_info->qop = digest_value;
				auth_info->qop_end = digest_value_end;

				char tmp_end = *digest_value_end;
				*digest_value_end = 0;	// Sanity

				// We need to search for this because there might be additional values for the field.
				char *qop_type_search = _StrStrIA( digest_value, "auth-int" );
				if ( qop_type_search != NULL )
				{
					qop_type_search[ 0 ] = '-';	// Set the string so we don't get a partial search match below.
					auth_info->qop_type = 2;
				}

				// If auth is specified, then we'll use that instead.
				do
				{
					qop_type_search = _StrStrIA( digest_value, "auth" );
					if ( qop_type_search != NULL )
					{
						if ( qop_type_search[ 4 ] == NULL ||
							 qop_type_search[ 4 ] == ' '  ||
							 qop_type_search[ 4 ] == '\t' ||
							 qop_type_search[ 4 ] == '\f' ||
							 qop_type_search[ 4 ] == ',' )
						{
							auth_info->qop_type = 1;
							break;
						}
						else
						{
							qop_type_search[ 0 ] = '-';	// Set the string so we don't get a partial search match below.
						}
					}
				}
				while ( qop_type_search != NULL );

				*digest_value_end = tmp_end;	// Restore.
			}

			if ( GetDigestValue( authenticate_header, "nc", 2, &digest_value, &digest_value_end ) != NULL )
			{
				char delimiter = digest_value[ 0 ];
				if ( delimiter == '\"' || delimiter == '\'' )
				{
					++digest_value;

					if ( *( digest_value_end - 1 ) == delimiter )
					{
						--digest_value_end;
					}
				}

				int digest_value_length = digest_value_end - digest_value;
				if ( digest_value_length > 10 )
				{
					digest_value_length = 10;
				}

				char nc[ 11 ];
				_memzero( nc, 11 );
				_memcpy_s( nc, 11, digest_value, digest_value_length );
				nc[ 10 ] = 0;	// Sanity

				auth_info->nc = _strtoul( nc, NULL, 16 );
			}

			if ( GetDigestValue( authenticate_header, "cnonce", 6, &digest_value, &digest_value_end ) != NULL )
			{
				char delimiter = digest_value[ 0 ];
				if ( delimiter == '\"' || delimiter == '\'' )
				{
					++digest_value;

					if ( *( digest_value_end - 1 ) == delimiter )
					{
						--digest_value_end;
					}
				}

				auth_info->cnonce = digest_value;
				auth_info->cnonce_end = digest_value_end;
			}

			*authenticate_header_end = tmp_end;	// Restore.

			return AUTH_TYPE_DIGEST;
		}
		else
		{
			return AUTH_TYPE_UNHANDLED;	// Unhandled.
		}
	}

	return AUTH_TYPE_NONE;
}

void GetHost( char *header, URL_INFO *url_info, bool is_secure )
{
	char *host_header = NULL;
	char *host_header_end = NULL;

	if ( GetHeaderValue( header, "Host", 4, &host_header, &host_header_end ) != NULL )
	{
		// Find the beginning of a port (if it was included).
		char *str_port_start = host_header_end - 1;
		while ( str_port_start >= host_header )
		{
			if ( *str_port_start == ':' )
			{
				// If we have a well formed IPv6 address, then see if there was a port assigned to it.
				if ( *host_header == '[' && str_port_start > host_header && *( str_port_start - 1 ) != ']' )
				{
					break;
				}

				char tmp_end = *host_header_end;
				*host_header_end = 0;	// Temporary string terminator.
				int num = _strtoul( str_port_start + 1, NULL, 10 );
				*host_header_end = tmp_end;	// Restore string.

				url_info->port = ( num > 65535 ? 0 : num );

				host_header_end = str_port_start;	// New end of host.

				break;
			}

			--str_port_start;
		}

		int host_length = host_header_end - host_header;

		url_info->host = ( char * )GlobalAlloc( GMEM_FIXED, sizeof( char ) * ( host_length + 1 ) );
		_memcpy_s( url_info->host, host_length + 1, host_header, host_length );
		url_info->host[ host_length ] = 0;	// Sanity

		if ( url_info->protocol == PROTOCOL_UNKNOWN )
		{
			if ( url_info->port == 80 )
			{
				url_info->protocol = PROTOCOL_HTTP;
			}
			else if ( url_info->port == 443 )
			{
				url_info->protocol = PROTOCOL_HTTPS;
			}
			else if ( is_secure )	// If the client has connected to us using SSL/TLS, then assume they want an HTTPS request.
			{
				if ( url_info->port == 0 )
				{
					url_info->port = 443;
				}

				url_info->protocol = PROTOCOL_HTTPS;
			}
			else
			{
				if ( url_info->port == 0 )
				{
					url_info->port = 80;
				}

				url_info->protocol = PROTOCOL_HTTP;
			}
		}
	}
}

bool GetTransferEncoding( char *header )
{
	char *transfer_encoding_header = NULL;
	char *transfer_encoding_header_end = NULL;

	if ( GetHeaderValue( header, "Transfer-Encoding", 17, &transfer_encoding_header, &transfer_encoding_header_end ) != NULL )
	{
		if ( ( transfer_encoding_header_end - transfer_encoding_header ) == 7 && _StrCmpNIA( transfer_encoding_header, "chunked", 7 ) == 0 )
		{
			return true;
		}
	}

	return false;
}

unsigned long long GetContentLength( char *header )
{
	char *content_length_header = NULL;
	char *content_length_header_end = NULL;

	if ( GetHeaderValue( header, "Content-Length", 14, &content_length_header, &content_length_header_end ) != NULL )
	{
		int content_length_length = ( content_length_header_end - content_length_header );
		if ( content_length_length > 20 )
		{
			content_length_length = 20;
		}

		char clength[ 21 ];
		_memzero( clength, 21 );
		_memcpy_s( clength, 21, content_length_header, content_length_length );
		clength[ 20 ] = 0;	// Sanity

		return strtoull( clength );
	}

	return 0;
}

// True if transfer has completed, false if not.
bool HasTransferCompleted( SOCKET_CONTEXT *context )
{
	// Save how much we've sent.
	context->header_info.content_sent += context->wsabuf_read.len;

	// If the transfer is a chunked transfer. A chunked transfer-encoding will take precedence over content-length if both are set in the header.
	if ( context->header_info.chunked_transfer )	
	{
		// Locate the chunked transfer terminator.
		unsigned char chunked_offset = ( unsigned char )min( 5, context->wsabuf_read.len );
		if ( chunked_offset == 5 )
		{
			_memcpy_s( context->header_info.chunked_ending, 5, &context->wsabuf_read.buf[ context->wsabuf_read.len - 5 ], 5 );

			context->header_info.chunked_ending_size = 5;
		}
		else	// The buffer is smaller than the terminator's size (5 bytes).
		{
			// If the current offset and the last size can hold the terminator.
			if ( chunked_offset + context->header_info.chunked_ending_size > 5 )
			{
				// Move the last valid bytes of the terminator buffer to its beginning.
				unsigned char t_offset = ( ( chunked_offset + context->header_info.chunked_ending_size ) - 5 );
				context->header_info.chunked_ending_size -= t_offset;

				_memmove( context->header_info.chunked_ending + t_offset, context->header_info.chunked_ending, context->header_info.chunked_ending_size );

				// Store the new bytes of the terminator.
				_memcpy_s( context->header_info.chunked_ending + context->header_info.chunked_ending_size, 5 - context->header_info.chunked_ending_size, &context->wsabuf_read.buf[ context->wsabuf_read.len - chunked_offset ], chunked_offset );

				context->header_info.chunked_ending_size = 5;
			}
			else	// We don't have a large enough terminator. Save what we have.
			{
				_memcpy_s( context->header_info.chunked_ending + context->header_info.chunked_ending_size, 5 - context->header_info.chunked_ending_size, &context->wsabuf_read.buf[ context->wsabuf_read.len - chunked_offset ], chunked_offset );

				context->header_info.chunked_ending_size += chunked_offset;
			}
		}

		// If we found the chunked transfer terminator.
		if ( context->header_info.chunked_ending_size == 5 && _memcmp( context->header_info.chunked_ending, "0\r\n\r\n", 5 ) == 0 )
		{
			return true;
		}
	}
	else	// If there was a content length field, see how much has been transfered.
	{
		// If we sent all the data from the server to the client.
		if ( context->header_info.content_sent >= context->header_info.content_length )
		{
			return true;
		}
	}

	return false;
}

void ParseURL( char *buffer, URL_INFO *url_info )
{
	if ( buffer == NULL || url_info == NULL )
	{
		return;
	}

	// Find the start of the host. (Resource is an absolute URI)
	char *str_pos_start = _StrStrA( buffer, "//" );
	if ( str_pos_start != NULL )
	{
		url_info->protocol = PROTOCOL_RELATIVE;

		if ( _StrCmpNA( buffer, "http", 4 ) == 0 )
		{
			if ( buffer[ 4 ] == 's' && buffer[ 5 ] == ':' )
			{
				url_info->protocol = PROTOCOL_HTTPS;
				url_info->port = 443;
			}
			else if ( buffer[ 4 ] == ':' )
			{
				url_info->protocol = PROTOCOL_HTTP;
				url_info->port = 80;
			}
		}

		str_pos_start += 2;

		// Find the end of the host.
		char *str_pos_end = _StrChrA( str_pos_start, '/' );
		if ( str_pos_end == NULL )
		{
			// See if there's a query string (this would technically not be valid). Would look like: www.test.com?foo=bar
			str_pos_end = _StrChrA( str_pos_start, '?' );
			if ( str_pos_end == NULL )
			{
				str_pos_end = str_pos_start + lstrlenA( str_pos_start );

				// Include the / as the resource.
				url_info->resource = ( char * )GlobalAlloc( GMEM_FIXED, sizeof( char ) * 2 );
				url_info->resource[ 0 ] = '/';
				url_info->resource[ 1 ] = 0;	// Sanity.
			}
			else
			{
				int resource_length = lstrlenA( str_pos_end );
				url_info->resource = ( char * )GlobalAlloc( GMEM_FIXED, sizeof( char ) * ( resource_length + 2 ) );	// Include the starting /.
				url_info->resource[ 0 ] = '/';
				_memcpy_s( url_info->resource + 1, resource_length + 1, str_pos_end, resource_length );
				url_info->resource[ resource_length + 1 ] = 0;	// Sanity.
			}
		}
		else
		{
			// Save the resource.
			url_info->resource = GlobalStrDupA( str_pos_end );
		}

		/*// Find the beginning of a port (if it was included).
		char *str_port_start = str_pos_end;
		while ( ( str_port_start - 1 ) >= str_pos_start )
		{
			if ( *( str_port_start - 1 ) == ':' )
			{
				if ( str_port_start > str_pos_start )
				{
					char tmp_end = *str_pos_end;
					*str_pos_end = 0;	// Temporary string terminator.
					int num = _strtoul( str_port_start, NULL, 10 );
					*str_pos_end = tmp_end;	// Restore string.

					url_info->port = ( num > 65535 ? 0 : num );

					str_pos_end = str_port_start - 1;	// New end of host.
				}

				break;
			}

			--str_port_start;
		}*/

		// Find the beginning of a port (if it was included).
		char *str_port_start = str_pos_end - 1;
		while ( str_port_start >= str_pos_start )
		{
			if ( *str_port_start == ':' )
			{
				// If we have a well formed IPv6 address, then see if there was a port assigned to it.
				if ( *str_pos_start == '[' && str_port_start > str_pos_start && *( str_port_start - 1 ) != ']' )
				{
					break;
				}

				char tmp_end = *str_pos_end;
				*str_pos_end = 0;	// Temporary string terminator.
				int num = _strtoul( str_port_start + 1, NULL, 10 );
				*str_pos_end = tmp_end;	// Restore string.

				url_info->port = ( num > 65535 ? 0 : num );

				str_pos_end = str_port_start;	// New end of host.

				break;
			}

			--str_port_start;
		}

		int host_length = str_pos_end - str_pos_start;

		// Save the host.
		url_info->host = ( char * )GlobalAlloc( GMEM_FIXED, sizeof( char ) * ( host_length + 1 ) );
		_memcpy_s( url_info->host, host_length + 1, str_pos_start, host_length );
		url_info->host[ host_length ] = 0;	// Sanity
	}
	else if ( buffer[ 0 ] == '/' )	// Resource is a relative URI that starts with a '/'
	{
		// Save the resource.
		url_info->resource = GlobalStrDupA( buffer );
	}
	else	// Resource is a relative URI that does not start with a '/'
	{
		int resource_length = lstrlenA( buffer ) + 1;	// Include the NULL terminator.

		url_info->resource = ( char * )GlobalAlloc( GMEM_FIXED, sizeof( char ) * ( resource_length + 1 ) );	// Include the '/'
		url_info->resource[ 0 ] = '/';

		_memcpy_s( url_info->resource + 1, resource_length, buffer, resource_length );
		url_info->resource[ resource_length ] = 0;	// Sanity.
	}
}


int ParseHTTPRequest( SOCKET_CONTEXT *context, char *buffer, unsigned int buffer_size )
{
	if ( context == NULL )
	{
		return -1;
	}

	bool reuse_connection = false;	// If a request has been made with the same protocol, host, and port, then reuse the connection to the server.
	bool is_authorized = true;		// Assume we're authorized for proxy authentication even if it's not enabled.

	if ( context->shared_request_info->request_type == REQUEST_TYPE_UNKNOWN )
	{
		if ( buffer_size >= 7 && _StrCmpNIA( buffer, "CONNECT", 7 ) == 0 )
		{
			context->shared_request_info->request_type = REQUEST_TYPE_CONNECT;
		}
		else if ( buffer_size >= 4 && _StrCmpNIA( buffer, "POST", 4 ) == 0 )
		{
			context->shared_request_info->request_type = REQUEST_TYPE_POST;
		}
		else// if ( buffer_size >= 3 && _StrCmpNIA( buffer, "GET", 3 ) == 0 )
		{
			context->shared_request_info->request_type = REQUEST_TYPE_GET;	// Handles HEAD, PUT, DELETE, etc.
		}
		/*else
		{
			context->shared_request_info->request_type = REQUEST_TYPE_UNSUPPORTED;
		}*/
	}

	char *end_of_header = NULL;

	if ( context->shared_request_info->request_type != REQUEST_TYPE_POST )
	{
		if ( buffer_size >= 4 && buffer[ buffer_size - 4 ] == '\r' &&
								 buffer[ buffer_size - 3 ] == '\n' &&
								 buffer[ buffer_size - 2 ] == '\r' &&
								 buffer[ buffer_size - 1 ] == '\n' )
		{
			end_of_header = buffer + ( buffer_size - 4 );
		}
	}
	else
	{
		end_of_header = _StrStrA( buffer, "\r\n\r\n" );
	}

	// Make sure we have the full header to process.
	if ( end_of_header != NULL )
	{
		//end_of_header[ 2 ] = 0;	// Temporary end.


		URL_INFO url_info;
		_memzero( &url_info, sizeof( URL_INFO ) );


		// Parse the absolute URIs of GET and POST requests.
		if ( context->shared_request_info->request_type == REQUEST_TYPE_GET || context->shared_request_info->request_type == REQUEST_TYPE_POST )
		{
			char *resource_url_end = _StrStrA( buffer, "\r\n" );
			if ( resource_url_end != NULL )
			{
				// Find the end of the Request URI.
				// It will end with a single space.
				while ( resource_url_end > buffer && *resource_url_end != ' ' )
				{
					--resource_url_end;
				}

				// Find the start of the Request URI.
				// It will start with a single space.
				char *resource_start = buffer;
				while ( resource_start < resource_url_end && *resource_start != ' ' )
				{
					++resource_start;
				}

				++resource_start;

				if ( resource_url_end > buffer )
				{
					*resource_url_end = 0;		// Temporary end.

					ParseURL( resource_start, &url_info );

					*resource_url_end = ' ';	// Restore.

					// This is so stupid. Match the relative URI protocol/port with the request URI protocol/port.
					if ( url_info.protocol == PROTOCOL_RELATIVE )
					{
						// Only set the port of it wasn't included.
						if ( url_info.port == 0 )
						{
							url_info.port = context->shared_request_info->url_info.port;
						}

						url_info.protocol = context->shared_request_info->url_info.protocol;
					}
				}
				else
				{
					return -1;	// Bad request format.
				}
			}
			else	// This shouldn't happen.
			{
				context->wsabuf_read.buf += buffer_size;
				context->wsabuf_read.len -= buffer_size;

				return 1;	// Need more data.
			}
		}


		if ( url_info.host == NULL )
		{
			GetHost( buffer, &url_info, ( context->ssl != NULL ? true : false ) );
		}


		// If a host has been set, then compare it to any previously set host.
		if ( url_info.host != NULL )
		{
			// Assume the resource has changed. It'll be set to url_info.resource below.
			if ( context->shared_request_info->url_info.resource != NULL )
			{
				GlobalFree( context->shared_request_info->url_info.resource );
			}

			// Do we already have a host set?
			if ( context->shared_request_info->url_info.host != NULL )
			{
				// See if any of the url info has changed (excluding the resource).
				if ( _strcmp( context->shared_request_info->url_info.host, url_info.host ) != 0 ||
					 context->shared_request_info->url_info.port != url_info.port ||
					 context->shared_request_info->url_info.protocol != url_info.protocol )
				{
					GlobalFree( context->shared_request_info->url_info.host );

					context->shared_request_info->url_info = url_info;

					context->create_new_connection = true;	// Since the url info has changed, we're going to need to make a new connection.
				}
				else	// If not, then free our temporary url info.
				{
					GlobalFree( url_info.host );

					context->shared_request_info->url_info.resource = url_info.resource;

					// Since the connection information (resource not included) has changed, we can reuse the connection (the request type should be switched to STEP_RELAY_DATA)
					reuse_connection = true;	
				}
			}
			else	// If no url info had been set, then use our temporary url info.
			{
				context->shared_request_info->url_info = url_info;
			}
		}
		else	// If no host was set, then we can't connect.
		{
			GlobalFree( url_info.resource );

			return -1;	// Bad URL.
		}



		// If we're doing a post request, then we need to know the size of the request.
		// This is to ensure that multiple posts to different hosts don't conflict.
		if ( context->shared_request_info->request_type == REQUEST_TYPE_POST )
		{
			if ( !context->header_info.chunked_transfer )
			{
				context->header_info.chunked_transfer = GetTransferEncoding( buffer );
			}

			if ( context->header_info.content_length == 0 )
			{
				context->header_info.content_length = GetContentLength( buffer );
			}
		}




		context->wsabuf_read.buf = buffer;
		context->wsabuf_read.len = buffer_size;

		// Change an absolute URI resource request into a normal resource request.
		// Do not modify the request if we're forwarding it to another proxy, or decrypting SSL/TLS connections.
		if ( ( ( ( context->proxy_type & PROXY_TYPE_HTTP ) && !cfg_forward_connections && context->shared_request_info->request_type != REQUEST_TYPE_CONNECT ) ||
			   ( ( context->proxy_type & PROXY_TYPE_HTTPS ) && !cfg_forward_connections_s && context->shared_request_info->request_type != REQUEST_TYPE_CONNECT ) ) &&
			!cfg_decrypt_tunnel )
		{
			char *request_type = _StrChrA( context->wsabuf_read.buf, ' '  );
			if ( request_type != NULL )
			{
				++request_type;

				char *resource_start = _StrStrA( request_type, "//" );
				if ( resource_start != NULL )
				{
					resource_start = _StrChrA( resource_start + 2, '/' );
					if ( resource_start != NULL )
					{
						unsigned int removed_length = ( resource_start - request_type );
						_memcpy_s( context->wsabuf_read.buf + removed_length, BUFFER_SIZE - removed_length, context->wsabuf_read.buf, ( request_type - context->wsabuf_read.buf ) );

						// Offset to the new start of the buffer.
						context->wsabuf_read.buf += removed_length;
						context->wsabuf_read.len -= removed_length;
					}
				}
			}
		}

		// If we require HTTP(S) authentication, then verify the supplied header value.
		if ( ( cfg_require_authentication && ( context->proxy_type & PROXY_TYPE_HTTP ) && context->shared_request_info->url_info.protocol == PROTOCOL_HTTP ) ||
			 ( cfg_require_authentication_s && ( context->proxy_type & PROXY_TYPE_HTTPS ) && context->shared_request_info->url_info.protocol == PROTOCOL_HTTPS ) )
		{
			is_authorized = false;	// Assume we're not authorized.

			AUTH_INFO auth_info;
			_memzero( &auth_info, sizeof( AUTH_INFO ) );
			unsigned char auth_type = GetAuthenticate( context->wsabuf_read.buf, &auth_info );

			if ( auth_type == AUTH_TYPE_BASIC )
			{
				char *authentication_key = NULL;
				unsigned long authentication_key_length = 0;

				if ( context->shared_request_info->url_info.protocol == PROTOCOL_HTTP )
				{
					authentication_key = g_authentication_key;
					authentication_key_length = g_authentication_key_length;
				}
				else// if ( context->shared_request_info->url_info.protocol == PROTOCOL_HTTPS )
				{
					authentication_key = g_authentication_key_s;
					authentication_key_length = g_authentication_key_length_s;
				}

				is_authorized = VerifyBasicAuthorization( authentication_key, authentication_key_length, &auth_info );
			}
			else if ( auth_type == AUTH_TYPE_DIGEST )
			{
				char *method = NULL;
				unsigned long method_length = 0;

				if ( context->shared_request_info->request_type == REQUEST_TYPE_GET )
				{
					method = "GET";
					method_length = 3;
				}
				else if ( context->shared_request_info->request_type == REQUEST_TYPE_POST )
				{
					method = "POST";
					method_length = 4;
				}
				else if ( context->shared_request_info->request_type == REQUEST_TYPE_CONNECT )
				{
					method = "CONNECT";
					method_length = 7;
				}

				if ( method != NULL )
				{
					char *username = NULL;
					char *password = NULL;
					char *nonce = NULL;
					char *opaque = NULL;
					unsigned long username_length = 0;
					unsigned long password_length = 0;
					unsigned long nonce_length = 0;
					unsigned long opaque_length = 0;

					if ( context->shared_request_info->url_info.protocol == PROTOCOL_HTTP )
					{
						username = cfg_auth_username;
						username_length = g_auth_username_length;

						password = cfg_auth_password;
						password_length = g_auth_password_length;

						nonce = g_nonce;
						nonce_length = g_nonce_length;

						opaque = g_opaque;
						opaque_length = g_opaque_length;
					}
					else// if ( context->shared_request_info->url_info.protocol == PROTOCOL_HTTPS )
					{
						username = cfg_auth_username_s;
						username_length = g_auth_username_length_s;

						password = cfg_auth_password_s;
						password_length = g_auth_password_length_s;

						nonce = g_nonce_s;
						nonce_length = g_nonce_length_s;

						opaque = g_opaque_s;
						opaque_length = g_opaque_length_s;
					}

					is_authorized = VerifyDigestAuthorization( username, username_length, password, password_length, nonce, nonce_length, opaque, opaque_length, method, method_length, &auth_info );
				}
			}

			if ( is_authorized )
			{
				// Remove the authorization field if we're not set to forward it.
				if ( ( context->shared_request_info->url_info.protocol == PROTOCOL_HTTP && !cfg_forward_authentication ) ||
					 ( context->shared_request_info->url_info.protocol == PROTOCOL_HTTPS && !cfg_forward_authentication_s ) )
				{
					auth_info.auth_end += 2;

					_memcpy_s( auth_info.auth_start, context->wsabuf_read.len - ( auth_info.auth_start - context->wsabuf_read.buf ), auth_info.auth_end, context->wsabuf_read.len - ( auth_info.auth_end - context->wsabuf_read.buf ) );

					context->wsabuf_read.len -= ( auth_info.auth_end - auth_info.auth_start );

					end_of_header = context->wsabuf_read.buf + ( context->wsabuf_read.len - 4 );
				}
			}
		}

//		end_of_header[ 2 ] = '\r';	// Restore.


		// Save the size of content that was sent in this request. (Used for POST requests.)
		context->header_info.content_sent = context->wsabuf_read.len - ( ( end_of_header + 4 ) - context->wsabuf_read.buf );


		// Based on the request type and protocol that's connected, determine the next connection step.
		if ( context->shared_request_info->request_type == REQUEST_TYPE_CONNECT )
		{
			if ( ( context->proxy_type & PROXY_TYPE_HTTPS ) && context->shared_request_info->url_info.protocol == PROTOCOL_HTTPS )
			{
				// We'll use this to distinguish if it's an HTTP or HTTPS proxy type if the proxy type happens to be PROXY_TYPE_HTTP_AND_HTTPS.
				context->proxy_type |= PROXY_TYPE_IS_HTTPS;

				if ( is_authorized )
				{
					if ( cfg_forward_connections_s )
					{
						context->shared_request_info->connection_steps = STEP_GOT_REQUEST;
					}
					else
					{
						context->shared_request_info->connection_steps = STEP_CONNECT_TO_SERVER;
					}
				}
				else
				{
					context->shared_request_info->connection_steps = STEP_PROXY_AUTH;
				}
			}
			else
			{
				context->shared_request_info->connection_steps = STEP_DENY_CONNECTION;
			}
		}
		else if ( reuse_connection )
		{
			if ( is_authorized )
			{
				context->shared_request_info->connection_steps = STEP_RELAY_DATA;
			}
			else
			{
				context->shared_request_info->connection_steps = STEP_PROXY_AUTH;
			}
		}
		else
		{
			if ( ( context->proxy_type & PROXY_TYPE_HTTP ) && context->shared_request_info->url_info.protocol == PROTOCOL_HTTP )
			{
				if ( is_authorized )
				{
					context->shared_request_info->connection_steps = STEP_GOT_REQUEST;
				}
				else
				{
					context->shared_request_info->connection_steps = STEP_PROXY_AUTH;
				}
			}
			else if ( ( ( context->proxy_type & PROXY_TYPE_HTTPS ) && context->shared_request_info->url_info.protocol == PROTOCOL_HTTPS ) && cfg_decrypt_tunnel )
			{
				// We'll use this to distinguish if it's an HTTP or HTTPS proxy type if the proxy type happens to be PROXY_TYPE_HTTP_AND_HTTPS.
				context->proxy_type |= PROXY_TYPE_IS_HTTPS;

				if ( is_authorized )
				{
					context->shared_request_info->connection_steps = STEP_GOT_REQUEST;
				}
				else
				{
					context->shared_request_info->connection_steps = STEP_PROXY_AUTH;
				}
			}
			else
			{
				context->shared_request_info->connection_steps = STEP_DENY_CONNECTION;
			}
		}

		if ( g_show_output )
		{
			EnterCriticalSection( &console_cs );
			SetConsoleTextAttribute( g_hOutput, FOREGROUND_INTENSITY );
			_printf( "Received %s request: %s://%s:%lu%s\r\n",
					( context->shared_request_info->request_type == REQUEST_TYPE_GET ? "GET" : ( context->shared_request_info->request_type == REQUEST_TYPE_POST ? "POST" : ( context->shared_request_info->request_type == REQUEST_TYPE_CONNECT ? "CONNECT" : "UNHANDLED" ) ) ),
					( context->shared_request_info->url_info.protocol == PROTOCOL_HTTP ? "http" : ( context->shared_request_info->url_info.protocol == PROTOCOL_HTTPS ? "https" : "unknown" ) ),
					  SAFESTRA( context->shared_request_info->url_info.host ),
					  context->shared_request_info->url_info.port,
					  SAFESTRA( context->shared_request_info->url_info.resource ) );
			SetConsoleTextAttribute( g_hOutput, ConsoleScreenBufferInfo.wAttributes );
			LeaveCriticalSection( &console_cs );
		}
	}
	else
	{
		// We can't hold any more of the request in the buffer.
		if ( BUFFER_SIZE - buffer_size == 0 )
		{
			return -1;	// Request is too large.
		}
		else	// If more data can be stored in the buffer, then request it.
		{
			context->wsabuf_read.buf += buffer_size;
			context->wsabuf_read.len -= buffer_size;

			return 1;	// Need more data.
		}
	}

	return 0;
}

char HandleRequest( SOCKET_CONTEXT *context )
{
	char status = 0;

	SECURITY_STATUS scRet = SEC_E_INTERNAL_ERROR;
	bool sent = false;
	int nRet = 0;
	DWORD dwFlags = 0;

	if ( context == NULL )
	{
		return -1;	// Cleanup both connections.
	}

	SOCKET_CONTEXT *context_c = NULL;	// The client that is connected to us.
	SOCKET_CONTEXT *context_s = NULL;	// The server that we are connected to.

	EnterCriticalSection( &context->shared_request_info->context_cs );

	if ( context->shared_request_info->connection_steps == STEP_DENY_CONNECTION )
	{
		context_c = context;

		context_c->wsabuf_write.buf = context->buffer_write;
		context_c->wsabuf_write.len = 201;

		_memcpy_s( context_c->wsabuf_write.buf, context_c->wsabuf_write.len,
									"HTTP/1.1 400 Bad Request\r\n" \
									"Content-Type: text/html\r\n" \
									"Content-Length: 108\r\n" \
									"Connection: close\r\n\r\n" \
									"<!DOCTYPE html><html><head><title>400 Bad Request</title></head><body><h1>400 Bad Request</h1></body></html>", context_c->wsabuf_write.len );

		context_c->next_operation_write = ( context_c->ssl != NULL ? IO_Shutdown : IO_Close );

		context_c->is_writing = true;

		// Reply to the client that the request was bad.
		if ( !TrySend( context_c ) )
		{
			context_c->is_writing = false;

			status = -1;
		}
	}
	else if ( context->shared_request_info->connection_steps == STEP_PROXY_AUTH )
	{
		context_c = context;

		context_c->wsabuf_write.buf = context->buffer_write;

		unsigned char auth_type = AUTH_TYPE_NONE;
		char *nonce = NULL;
		char *opaque = NULL;

		if ( ( context->proxy_type & PROXY_TYPE_HTTP ) && context->shared_request_info->url_info.protocol == PROTOCOL_HTTP )
		{
			auth_type = cfg_auth_type;
			nonce = g_nonce;
			opaque = g_opaque;
		}
		else if ( ( context->proxy_type & PROXY_TYPE_HTTPS ) && context->shared_request_info->url_info.protocol == PROTOCOL_HTTPS )
		{
			auth_type = cfg_auth_type_s;
			nonce = g_nonce_s;
			opaque = g_opaque_s;
		}

		if ( auth_type == AUTH_TYPE_BASIC )
		{
			context_c->wsabuf_write.len = 320;

			_memcpy_s( context_c->wsabuf_write.buf, context_c->wsabuf_write.len,
										"HTTP/1.1 407 Proxy Authentication Required\r\n" \
										"Content-Type: text/html\r\n" \
										"Proxy-Authenticate: Basic realm=\"Proxy Authentication Required\"\r\n" \
										"Content-Length: 144\r\n" \
										"Connection: close\r\n\r\n" \
										"<!DOCTYPE html><html><head><title>407 Proxy Authentication Required</title></head><body><h1>407 Proxy Authentication Required</h1></body></html>", context_c->wsabuf_write.len );
		}
		else if ( auth_type == AUTH_TYPE_DIGEST )
		{
			context_c->wsabuf_write.len = __snprintf( context_c->wsabuf_write.buf, BUFFER_SIZE,
										"HTTP/1.1 407 Proxy Authentication Required\r\n" \
										"Content-Type: text/html\r\n" \
										"Proxy-Authenticate: Digest " \
															"realm=\"Proxy Authentication Required\", " \
															"algorithm=MD5-sess, " \
															"qop=\"auth\", " \
															"nonce=\"%s\", " \
															"opaque=\"%s\"\r\n" \
										"Content-Length: 144\r\n" \
										"Connection: close\r\n\r\n" \
										"<!DOCTYPE html><html><head><title>407 Proxy Authentication Required</title></head><body><h1>407 Proxy Authentication Required</h1></body></html>", nonce, opaque );
		}
		else
		{
			context_c->wsabuf_write.len = 231;

			_memcpy_s( context_c->wsabuf_write.buf, context_c->wsabuf_write.len,
										"HTTP/1.1 500 Internal Server Error\r\n" \
										"Content-Type: text/html\r\n" \
										"Content-Length: 128\r\n" \
										"Connection: close\r\n\r\n" \
										"<!DOCTYPE html><html><head><title>500 Internal Server Error</title></head><body><h1>500 Internal Server Error</h1></body></html>", context_c->wsabuf_write.len );
		}

		context_c->next_operation_write = ( context_c->ssl != NULL ? IO_Shutdown : IO_Close );

		context_c->is_writing = true;

		// Reply to the client that the request was bad.
		if ( !TrySend( context_c ) )
		{
			context_c->is_writing = false;

			status = -1;
		}
	}
	else if ( context->shared_request_info->connection_steps == STEP_CONNECT_TO_SERVER )
	{
		context_c = context;

		context_c->wsabuf_write.buf = context->buffer_write;
		context_c->wsabuf_write.len = 19;

		_memcpy_s( context_c->wsabuf_write.buf, context_c->wsabuf_write.len, "HTTP/1.1 200 OK\r\n\r\n", context_c->wsabuf_write.len );

		context_c->next_operation_write = IO_GetRequest;

		context_c->is_writing = true;

		// Reply to the client that we can tunnel the connection.
		if ( TrySend( context_c ) )
		{
			context_c->current_operation_read = IO_GetRequest;

			context_c->wsabuf_read.buf = context_c->buffer_read;
			context_c->wsabuf_read.len = BUFFER_SIZE;

			context_c->is_reading = true;

			// If the reply was successful, then post a read.
			if ( !TryReceive( context_c ) )
			{
				context_c->is_reading = false;

				status = -1;
			}
		}
		else	// We couldn't send the reply.
		{
			context_c->is_writing = false;

			status = -1;
		}
	}
	else if ( context->shared_request_info->connection_steps == STEP_GOT_REQUEST )
	{
		if ( context->shared_request_info->request_type == REQUEST_TYPE_CONNECT && cfg_decrypt_tunnel )
		{
			context->shared_request_info->request_type = REQUEST_TYPE_UNKNOWN;
			context->shared_request_info->connection_steps = STEP_GET_REQUEST;

			// We don't want to reuse the url information.
			GlobalFree( context->shared_request_info->url_info.host );
			context->shared_request_info->url_info.host = NULL;
			GlobalFree( context->shared_request_info->url_info.resource );
			context->shared_request_info->url_info.resource = NULL;
			context->shared_request_info->url_info.port = 0;
			context->shared_request_info->url_info.protocol = PROTOCOL_UNKNOWN;

			DWORD protocol = 0;
			switch ( cfg_protocol )
			{
				case 4:	protocol |= SP_PROT_TLS1_2;
				case 3:	protocol |= SP_PROT_TLS1_1;
				case 2:	protocol |= SP_PROT_TLS1;
				case 1:	protocol |= SP_PROT_SSL3;
				case 0:	{ if ( cfg_protocol < 4 ) { protocol |= SP_PROT_SSL2; } }
			}

			SSL *ssl = SSL_new( protocol, true );
			if ( ssl != NULL )
			{
				ssl->s = context->socket;

				context->ssl = ssl;

				/////////////////////

				// Begin our handshake.
				ssl->acd.fInitContext = true;

				ssl->cbIoBuffer = 0;

				ssl->acd.fDoRead = true;

				ssl->acd.scRet = SEC_I_CONTINUE_NEEDED;
				scRet = ssl->acd.scRet;

				// If buffer not large enough reallocate buffer
				if ( ssl->sbIoBuffer <= ssl->cbIoBuffer )
				{
					ssl->sbIoBuffer += 2048;
					if ( ssl->pbIoBuffer == NULL )
					{
						ssl->pbIoBuffer = ( PUCHAR )GlobalAlloc( GPTR, ssl->sbIoBuffer );
					}
					else
					{
						ssl->pbIoBuffer = ( PUCHAR )GlobalReAlloc( ssl->pbIoBuffer, ssl->sbIoBuffer, GMEM_MOVEABLE );
					}
				}

				DWORD bytes_received = min( context->wsabuf_read.len, ssl->sbIoBuffer );

				_memcpy_s( context->ssl->pbIoBuffer, ssl->sbIoBuffer, context->wsabuf_read.buf, bytes_received );

				/////////////////////

				InterlockedIncrement( &context->pending_operations );

				context->current_operation_read = IO_ServerHandshakeReply;

				PostQueuedCompletionStatus( g_hIOCP, bytes_received, ( ULONG_PTR )context, &context->overlapped_read );
			}
			else
			{
				status = -1;
			}
		}
		else	// Establish a connection to the remote server and send it the request we got from the client (connected to our proxy).
		{
			context_c = context;
			context_s = context->relay_context;

			if ( context_s != NULL )
			{
				// If the server is not writing, then close it so we can create a new server connection.
				if ( !context_s->is_writing )
				{
					if ( context_c->create_new_connection )
					{
						context_c->create_new_connection = false;

						if ( context_s->relay_context != NULL )
						{
							context_s->relay_context->relay_context = NULL;
							context_s->relay_context = NULL;
						}

						BeginClose( context_s, ( context_s->ssl != NULL ? IO_Shutdown : IO_Close ) );

						context_s = NULL;
					}
				}
				else	// If the server is in the process of writing, then call HandleRequest again after it finishes.
				{
					context_s->do_write = true;
				}
			}

			if ( context_s == NULL )
			{
				context_s = CreateSocketContext();
				context_s->context_node.data = context_s;

				EnterCriticalSection( &context_list_cs );

				DLL_AddNode( &context_list, &context_s->context_node, -1 );

				EnableTimer( true );

				LeaveCriticalSection( &context_list_cs );

				context_c->relay_context = context_s;
				context_s->relay_context = context_c;

				context_s->header_info = context_c->header_info;

				// If the client connection is sending POST data to the server, then find out if it all of it will have been sent.
				// We need to know when it's done so that new requests can be parsed correctly if the client reuses the connection.
				if ( context_s->header_info.content_sent >= context_s->header_info.content_length )
				{
					context_s->post_completed = true;
				}

				context_s->shared_request_info = context_c->shared_request_info;
				++context_s->shared_request_info->shared_count;

				context_s->proxy_type = context_c->proxy_type;

				// context_c's wsabuf_read will have been set in ParseHTTPRequest. We want context_s to inherit the values.

				// The wsa_write buffer will get mangled during an SSL/TLS handshake.
				// We'll save the offsets so that we can send the data after the handshake.
				context_s->temp_wsabuf_write = context_c->wsabuf_read;

				// Swap buffers.
				CHAR *tmp_buffer = context_c->buffer_read;
				context_c->buffer_read = context_s->buffer_write;
				context_s->buffer_write = tmp_buffer;

				context_s->wsabuf_write = context_c->wsabuf_read;

				context_c->wsabuf_read.buf = context_c->buffer_read;
				context_c->wsabuf_read.len = BUFFER_SIZE;

				//context_s->is_writing = true;

				// Connect to the remote server.
				if ( CreateConnection( context_s, context_c->shared_request_info->url_info.host, context_c->shared_request_info->url_info.port ) )
				{
					// Post a pending read for the client.
					context_c->current_operation_read = IO_GetRequest;

					context_c->wsabuf_read.buf = context_c->buffer_read;
					context_c->wsabuf_read.len = BUFFER_SIZE;

					context_c->do_read = true;

					context_c->is_reading = true;

					if ( !TryReceive( context_c ) )
					{
						context_c->do_read = false;

						context_c->is_reading = false;

						status = -1;
					}
				}
				else	// A connection could not be established.
				{
					//context_s->is_writing = false;

					status = -1;
				}
			}
		}
	}
	else
	{
		SOCKET_CONTEXT *context_a = context;
		SOCKET_CONTEXT *context_b = context->relay_context;

		if ( context_b != NULL )
		{
			// Make sure the client/server is not already writing.
			if ( !context_b->is_writing )
			{
				if ( ( ( context->proxy_type & PROXY_TYPE_HTTP ) && !cfg_forward_connections ) ||
					 ( ( context->proxy_type & PROXY_TYPE_HTTPS ) && !cfg_forward_connections_s ) )
				{
					// If the client connection is sending POST data to the server, then find out if it all of it will have been sent.
					// We need to know when it's done so that new requests can be parsed correctly if the client reuses the connection.
					if ( context->context_type == CONTEXT_TYPE_SERVER && context->shared_request_info->request_type == REQUEST_TYPE_POST )
					{
						context->post_completed = HasTransferCompleted( context );
					}
				}

				// Swap buffers.
				CHAR *tmp_buffer = context_a->buffer_read;
				context_a->buffer_read = context_b->buffer_write;
				context_b->buffer_write = tmp_buffer;

				context_b->wsabuf_write = context_a->wsabuf_read;

				context_a->wsabuf_read.buf = context_a->buffer_read;
				context_a->wsabuf_read.len = BUFFER_SIZE;

				// Write the data we received from the server/client to the client/server.
				context_b->is_writing = true;

				// Since we're writing now, we don't need to wait.
				context_b->do_write = false;

				context_b->next_operation_write = IO_ProcessWrite;

				context_b->do_read = true;	// Attempt to read from the client/server if our send succeeds.

				if ( TrySend( context_b ) )
				{
					// Post a read for the server/client connection.
					if ( context_a->do_read )
					{
						context_a->is_reading = true;

						context_a->current_operation_read = IO_GetRequest;

						if ( !TryReceive( context_a ) )
						{
							context_a->is_reading = false;

							context_a->do_read = false;

							status = -1;
						}
					}
				}
				else	// The send failed. Don't read from the client/server anymore.
				{
					context_b->is_writing = false;

					context_b->do_read = false;

					status = -1;
				}
			}
			else	// New server/client data is waiting to be written to the client/server.
			{
				context_b->do_write = true;
			}
		}
		else	// The client/server is not connected.
		{
			status = -1;
		}
	}

	LeaveCriticalSection( &context->shared_request_info->context_cs );

	return status;
}
