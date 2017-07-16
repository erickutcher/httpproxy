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
#include "http.h"
#include "lite_crypt32.h"
#include "lite_advapi32.h"
#include "lite_normaliz.h"
#include "utilities.h"

HANDLE g_hIOCP = NULL;
SOCKET g_listen_socket = INVALID_SOCKET;
SOCKET g_listen_socket_s = INVALID_SOCKET;
bool g_use_ipv6 = false;
bool g_use_ipv6_s = false;

PCCERT_CONTEXT g_pCertContext = NULL;

WSAEVENT g_hCleanupEvent[ 1 ];

HANDLE g_timeout_semaphore = NULL;

bool g_shutdown_server = true;
bool g_restart_server = false;

bool in_server_thread = false;

DoublyLinkedList *context_list = NULL;

SOCKET_CONTEXT *listen_context = NULL;
SOCKET_CONTEXT *listen_context_s = NULL;

CHAR listen_addr_data[ 14 ];
CHAR listen_addr_data_s[ 14 ];

void FreeContexts();
void FreeListenContexts();

CRITICAL_SECTION context_list_cs;		// Guard access to the global context list.

LPFN_CONNECTEX _ConnectEx = NULL;
LPFN_ACCEPTEX _AcceptEx = NULL;

bool g_timer_running = false;

// This should be done in a critical section.
void EnableTimer( bool timer_state )
{
	// Trigger the timer out of its infinite wait.
	if ( timer_state )
	{
		if ( !g_timer_running )
		{
			g_timer_running = true;

			if ( g_timeout_semaphore != NULL )
			{
				ReleaseSemaphore( g_timeout_semaphore, 1, NULL );
			}
		}
	}
	else	// Let the timer complete its current task and then wait indefinitely.
	{
		g_timer_running = false;
	}
}

// This will time out connections that aren't closed by the server or the client. It's not the proxy's job to know when to close them.
DWORD WINAPI Timeout( LPVOID WorkThreadContext )
{
	bool run_timer = g_timer_running;

	while ( !g_shutdown_server )
	{
		WaitForSingleObject( g_timeout_semaphore, ( run_timer ? 1000 : INFINITE ) );

		if ( g_shutdown_server )
		{
			break;
		}

		// This will allow the timer to go through at least one loop after it's been disabled (g_timer_running == false).
		run_timer = g_timer_running;

		// Timeout() and HandleRequest() will deadlock if we don't use TryEnterCriticalSection.
		if ( TryEnterCriticalSection( &context_list_cs ) == TRUE )
		{
			DoublyLinkedList *context_node = context_list;

			while ( context_node != NULL )
			{
				if ( g_shutdown_server )
				{
					break;
				}

				SOCKET_CONTEXT *context = ( SOCKET_CONTEXT * )context_node->data;

				// Timeout() and HandleRequest() will deadlock if we don't use TryEnterCriticalSection.
				if ( TryEnterCriticalSection( &context->shared_request_info->context_cs ) == TRUE )
				{
					if ( context != NULL && context->timed_out == TIME_OUT_FALSE )
					{
						if ( context->current_operation_read == IO_GetRequest || context->current_operation_write == IO_ProcessWrite )
						{
							if ( context->timeout >= cfg_timeout )
							{
								// If the connection hasn't already been forcefully closed, then set the timeout status and shutdown/close it.
								if ( !context->finish_writing )
								{
									context->timed_out = TIME_OUT_TRUE;

									BeginClose( context, ( context->ssl != NULL ? IO_Shutdown : IO_Close ) );
								}
							}
							else
							{
								InterlockedIncrement( &context->timeout );
							}
						}
						else if ( cfg_retry_client_timeout && context->context_type == CONTEXT_TYPE_CLIENT && context->current_operation_write == IO_Connect )	// A client connection (remote server) is stuck in the Connect state.
						{
							// Reset the server connection timeout so that we can retry the client connection from a fresh state.
							if ( context->relay_context != NULL )
							{
								InterlockedExchange( &context->relay_context->timeout, 0 );	// Reset timeout counter.
							}

							// If the connection timed out, then we'll shutdown/close it normally.
							if ( context->timeout >= cfg_timeout )
							{
								context->timed_out = TIME_OUT_RETRY;

								BeginClose( context, ( context->ssl != NULL ? IO_Shutdown : IO_Close ) );
							}
							else
							{
								InterlockedIncrement( &context->timeout );
							}
						}
					}

					LeaveCriticalSection( &context->shared_request_info->context_cs );
				}

				context_node = context_node->next;
			}

			LeaveCriticalSection( &context_list_cs );
		}
	}

	CloseHandle( g_timeout_semaphore );
	g_timeout_semaphore = NULL;

	ExitThread( 0 );
	return 0;
}

DWORD WINAPI IOCPServer( LPVOID pArgs )
{
	in_server_thread = true;

	g_shutdown_server = false;
	g_restart_server = true;

	if ( ws2_32_state == WS2_32_STATE_SHUTDOWN )
	{
		#ifndef WS2_32_USE_STATIC_LIB
			if ( !InitializeWS2_32() ){ goto EXIT_SERVER; }
		#else
			StartWS2_32();
		#endif
	}

	if ( !LoadConnectEx() ) { goto EXIT_SERVER; }

	if ( ssl_state == SSL_STATE_SHUTDOWN )
	{
		if ( SSL_library_init() == 0 ){ goto EXIT_SERVER; }
	}

	if ( cfg_use_ssl && g_pCertContext == NULL )
	{
		if ( cfg_certificate_type == 1 )	// PKCS #12 File.
		{
			g_pCertContext = LoadPKCS12( cfg_certificate_pkcs_file_name, cfg_certificate_pkcs_password );
		}
		else	// Public/Private Key Pair.
		{
			g_pCertContext = LoadPublicPrivateKeyPair( cfg_certificate_cer_file_name, cfg_certificate_key_file_name );
		}

		if ( g_pCertContext == NULL )
		{
			goto EXIT_SERVER;
		}
	}

	InitializeCriticalSection( &context_list_cs );

	HANDLE *g_ThreadHandles = ( HANDLE * )GlobalAlloc( GMEM_FIXED, sizeof( HANDLE ) * cfg_thread_count );

	for ( unsigned int i = 0; i < cfg_thread_count; ++i )
	{
		g_ThreadHandles[ i ] = INVALID_HANDLE_VALUE;
	}

	g_hCleanupEvent[ 0 ] = _WSACreateEvent();
	if ( g_hCleanupEvent[ 0 ] == WSA_INVALID_EVENT )
	{
		g_restart_server = false;
	}

	g_timeout_semaphore = CreateSemaphore( NULL, 0, 1, NULL );

	//CloseHandle( _CreateThread( NULL, 0, Timeout, NULL, 0, NULL ) );
	HANDLE timeout_handle = _CreateThread( NULL, 0, Timeout, NULL, 0, NULL );
	SetThreadPriority( timeout_handle, THREAD_PRIORITY_LOWEST );
	CloseHandle( timeout_handle );

	while ( g_restart_server )
	{
		EnterCriticalSection( &console_cs );
		SetConsoleTextAttribute( g_hOutput, FOREGROUND_GREEN | FOREGROUND_INTENSITY );
		_wprintf( L"*** Server Started ***\r\n" );
		SetConsoleTextAttribute( g_hOutput, ConsoleScreenBufferInfo.wAttributes );
		LeaveCriticalSection( &console_cs );

		g_shutdown_server = false;
		g_restart_server = false;

		g_use_ipv6 = false;
		g_use_ipv6_s = false;

		g_hIOCP = CreateIoCompletionPort( INVALID_HANDLE_VALUE, NULL, 0, 0 );
		if ( g_hIOCP == NULL )
		{
			break;
		}

		_WSAResetEvent( g_hCleanupEvent[ 0 ] );

		for ( DWORD dwCPU = 0; dwCPU < cfg_thread_count; ++dwCPU )
		{
			HANDLE hThread;
			DWORD dwThreadId;

			// Create worker threads to service the overlapped I/O requests.
			hThread = _CreateThread( NULL, 0, IOCPConnection, g_hIOCP, 0, &dwThreadId );
			if ( hThread == NULL )
			{
				break;
			}

			g_ThreadHandles[ dwCPU ] = hThread;
			hThread = INVALID_HANDLE_VALUE;
		}

		char listen_status = LA_STATUS_UNKNOWN, listen_status_s = LA_STATUS_UNKNOWN,
			 accept_status = LA_STATUS_UNKNOWN, accept_status_s = LA_STATUS_UNKNOWN;

		if ( cfg_proxy_type & PROXY_TYPE_HTTP )
		{
			listen_status = CreateListenSocket( ( g_hostname_ip_address != NULL ? g_hostname_ip_address : cfg_hostname_ip_address ), cfg_port, g_use_ipv6, PROXY_TYPE_HTTP );
		}

		if ( cfg_proxy_type & PROXY_TYPE_HTTPS )
		{
			listen_status_s = CreateListenSocket( ( g_hostname_ip_address_s != NULL ? g_hostname_ip_address_s : cfg_hostname_ip_address_s ), cfg_port_s, g_use_ipv6_s, PROXY_TYPE_HTTPS );
		}

		if ( listen_status == LA_STATUS_FAILED || listen_status_s == LA_STATUS_FAILED )	// One or both of the listening sockets failed.
		{
			EnterCriticalSection( &console_cs );
			SetConsoleTextAttribute( g_hOutput, FOREGROUND_RED | FOREGROUND_INTENSITY );
			if ( listen_status == LA_STATUS_FAILED && listen_status_s == LA_STATUS_FAILED )
			{
				_wprintf( L"Unable to create HTTP and HTTPS listening sockets.\r\n" );
			}
			else
			{
				_wprintf( L"Unable to create HTTP%s listening socket.\r\n", ( listen_status_s == LA_STATUS_FAILED ? L"S" : L"" ) );
			}
			SetConsoleTextAttribute( g_hOutput, ConsoleScreenBufferInfo.wAttributes );
			LeaveCriticalSection( &console_cs );
		}
		else	// Create the accept socket.
		{
			if ( listen_status == LA_STATUS_DUPLICATE || listen_status_s == LA_STATUS_DUPLICATE )	// One of the listen sockets matches the host and port of the other.
			{
				accept_status = CreateAcceptSocket( g_use_ipv6, PROXY_TYPE_HTTP_AND_HTTPS );
			}
			else
			{
				if ( listen_status == LA_STATUS_OK )
				{
					accept_status = CreateAcceptSocket( g_use_ipv6, PROXY_TYPE_HTTP );
				}

				if ( listen_status_s == LA_STATUS_OK && accept_status != LA_STATUS_FAILED )
				{
					accept_status_s = CreateAcceptSocket( g_use_ipv6_s, PROXY_TYPE_HTTPS );
				}
			}

			if ( accept_status != LA_STATUS_FAILED && accept_status_s != LA_STATUS_FAILED )
			{
				_WSAWaitForMultipleEvents( 1, g_hCleanupEvent, TRUE, WSA_INFINITE, FALSE );
			}
			else
			{
				EnterCriticalSection( &console_cs );
				SetConsoleTextAttribute( g_hOutput, FOREGROUND_RED | FOREGROUND_INTENSITY );
				if ( listen_status == LA_STATUS_DUPLICATE || listen_status_s == LA_STATUS_DUPLICATE )
				{
					_wprintf( L"Unable to accept connection on HTTP / HTTPS listening socket.\r\n" );
					
				}
				else
				{
					_wprintf( L"Unable to accept connection on HTTP%s listening socket.\r\n", ( accept_status_s == LA_STATUS_FAILED ? L"S" : L"" ) );
				}
				SetConsoleTextAttribute( g_hOutput, ConsoleScreenBufferInfo.wAttributes );
				LeaveCriticalSection( &console_cs );
			}
		}

		g_shutdown_server = true;

		// Cause worker threads to exit
		if ( g_hIOCP != NULL )
		{
			for ( DWORD i = 0; i < cfg_thread_count; ++i )
			{
				PostQueuedCompletionStatus( g_hIOCP, 0, 0, NULL );
			}
		}

		// Make sure worker threads exit.
		if ( WaitForMultipleObjects( cfg_thread_count, g_ThreadHandles, TRUE, 1000 ) == WAIT_OBJECT_0 )
		{
			for ( DWORD i = 0; i < cfg_thread_count; ++i )
			{
				if ( g_ThreadHandles[ i ] != INVALID_HANDLE_VALUE )
				{
					CloseHandle( g_ThreadHandles[ i ] );
					g_ThreadHandles[ i ] = INVALID_HANDLE_VALUE;
				}
			}
		}

		if ( g_listen_socket != INVALID_SOCKET )
		{
			_shutdown( g_listen_socket, SD_BOTH );
			_closesocket( g_listen_socket );
			g_listen_socket = INVALID_SOCKET;
		}

		if ( g_listen_socket_s != INVALID_SOCKET )
		{
			_shutdown( g_listen_socket_s, SD_BOTH );
			_closesocket( g_listen_socket_s );
			g_listen_socket_s = INVALID_SOCKET;
		}

		FreeListenContexts();

		FreeContexts();

		if ( g_hIOCP != NULL )
		{
			CloseHandle( g_hIOCP );
			g_hIOCP = NULL;
		}
	}

	// Exit our polling thread if it's active.
	if ( g_timeout_semaphore != NULL )
	{
		ReleaseSemaphore( g_timeout_semaphore, 1, NULL );
	}

	if ( cfg_use_ssl )
	{
		if ( g_pCertContext != NULL )
		{
			_CertFreeCertificateContext( g_pCertContext );
			g_pCertContext = NULL;
		}
	}

	GlobalFree( g_ThreadHandles );
	g_ThreadHandles = NULL;

	if ( g_hCleanupEvent[ 0 ] != WSA_INVALID_EVENT )
	{
		_WSACloseEvent( g_hCleanupEvent[ 0 ] );
		g_hCleanupEvent[ 0 ] = WSA_INVALID_EVENT;
	}

	DeleteCriticalSection( &context_list_cs );

EXIT_SERVER:

	g_shutdown_server = true;
	g_restart_server = false;

	EnterCriticalSection( &console_cs );
	SetConsoleTextAttribute( g_hOutput, FOREGROUND_RED | FOREGROUND_INTENSITY );
	_wprintf( L"*** Server Shut Down ***\r\n" );
	SetConsoleTextAttribute( g_hOutput, ConsoleScreenBufferInfo.wAttributes );
	LeaveCriticalSection( &console_cs );

	in_server_thread = false;

	_ExitThread( 0 );
	return 0;
}

SOCKET CreateSocket( bool IPv6 )
{
	int nZero = 0;
	SOCKET socket = INVALID_SOCKET;

	socket = _WSASocketW( ( IPv6 ? AF_INET6 : AF_INET ), SOCK_STREAM, IPPROTO_IP, NULL, 0, WSA_FLAG_OVERLAPPED ); 
	if ( socket != INVALID_SOCKET )
	{
		// Disable send buffering on the socket.
		_setsockopt( socket, SOL_SOCKET, SO_SNDBUF, ( char * )&nZero, sizeof( nZero ) );
	}

	return socket;
}

SECURITY_STATUS DecryptRecv( SOCKET_CONTEXT *context, DWORD &io_size, bool &extra_data )
{
	SECURITY_STATUS scRet = SEC_E_INTERNAL_ERROR;

	WSABUF wsa_decrypt;

	DWORD bytes_decrypted = 0;

	SSL *ssl = context->ssl;

	if ( ssl->rd.scRet == SEC_E_INCOMPLETE_MESSAGE )
	{
		ssl->cbIoBuffer += io_size;
	}
	else
	{
		ssl->cbIoBuffer = io_size;
	}

	io_size = 0;
	extra_data = false;

	wsa_decrypt = context->wsabuf_read;

	// Decrypt our buffer.
	while ( ssl->pbIoBuffer != NULL /*&& ssl->cbIoBuffer > 0*/ )
	{
		scRet = SSL_WSARecv_Decrypt( ssl, &wsa_decrypt, bytes_decrypted );

		io_size += bytes_decrypted;

		wsa_decrypt.buf += bytes_decrypted;
		wsa_decrypt.len -= bytes_decrypted;

		switch ( scRet )
		{
			// We've successfully decrypted a portion of the buffer.
			case SEC_E_OK:
			{
				// Decrypt more records if there are any.
				continue;
			}
			break;

			// The message was decrypted, but not all of it was copied to our wsabuf.
			// There may be incomplete records left to decrypt. DecryptRecv must be called again after processing wsabuf.
			case SEC_I_CONTINUE_NEEDED:
			{
				extra_data = true;

				return scRet;
			}
			break;
			// The message was incomplete. Request more data from the server.
			case SEC_E_INCOMPLETE_MESSAGE:
			{
				return scRet;
			}
			break;

			// Client wants us to perform another handshake.
			case SEC_I_RENEGOTIATE:
			{
				return scRet;
			}
			break;

			//case SEC_I_CONTEXT_EXPIRED:
			default:
			{
				ssl->cbIoBuffer = 0;

				return scRet;
			}
			break;
		}
	}

	ssl->cbIoBuffer = 0;

	return scRet;
}

bool TrySend( SOCKET_CONTEXT *context )
{
	if ( context == NULL )
	{
		return false;
	}

	int nRet = 0;
	SECURITY_STATUS scRet = SEC_E_INTERNAL_ERROR;

	bool sent = true;

	InterlockedIncrement( &context->pending_operations );

	if ( context->ssl == NULL )
	{
		context->current_operation_write = IO_Write;

		nRet = _WSASend( context->socket, &context->wsabuf_write, 1, NULL, 0, &context->overlapped_write, NULL );
		if ( nRet == SOCKET_ERROR && ( _WSAGetLastError() != ERROR_IO_PENDING ) )
		{
			sent = false;
		}
	}
	else
	{
		/*scRet =*/ SSL_WSASend( context, &context->wsabuf_write, sent );
		/*if ( scRet != SEC_E_OK )
		{
			sent = false;
		}*/
	}

	if ( !sent )
	{
		InterlockedDecrement( &context->pending_operations );
	}

	return sent;
}

bool TryReceive( SOCKET_CONTEXT *context )
{
	if ( context == NULL )
	{
		return false;
	}

	int nRet = 0;
	SECURITY_STATUS scRet = SEC_E_INTERNAL_ERROR;
	DWORD dwFlags = 0;

	bool sent = true;

	InterlockedIncrement( &context->pending_operations );

	if ( context->ssl == NULL )
	{
		nRet = _WSARecv( context->socket, &context->wsabuf_read, 1, NULL, &dwFlags, &context->overlapped_read, NULL );
		if ( nRet == SOCKET_ERROR && ( _WSAGetLastError() != ERROR_IO_PENDING ) )
		{
			sent = false;
		}
	}
	else
	{
		/*scRet =*/ SSL_WSARecv( context, sent );
		/*if ( scRet != SEC_E_OK )
		{
			sent = false;
		}*/
	}

	if ( !sent )
	{
		InterlockedDecrement( &context->pending_operations );
	}

	return sent;
}

void BeginClose( SOCKET_CONTEXT *context, IO_OPERATION io_operation )
{
	if ( context != NULL )
	{
		EnterCriticalSection( &context->shared_request_info->context_cs );

		if ( !context->finish_writing )
		{
			context->finish_writing = true;

			if ( !context->is_writing )
			{
				InterlockedIncrement( &context->pending_operations );

				context->current_operation_read = io_operation;
				context->current_operation_write = io_operation;
				context->next_operation_write = io_operation;

				PostQueuedCompletionStatus( g_hIOCP, 0, ( ULONG_PTR )context, &context->overlapped_read );
			}
		}

		LeaveCriticalSection( &context->shared_request_info->context_cs );
	}
}

DWORD WINAPI IOCPConnection( LPVOID WorkThreadContext )
{
	HANDLE hIOCP = ( HANDLE )WorkThreadContext;
	WSAOVERLAPPED *overlapped = NULL;
	DWORD io_size = 0;
	SOCKET_CONTEXT *context = NULL;

	BOOL completion_status = TRUE;

	bool use_ssl = false;

	SECURITY_STATUS scRet = SEC_E_INTERNAL_ERROR;
	bool sent = false;
	int nRet = 0;
	DWORD dwFlags = 0;

	IO_OPERATION *current_operation = NULL;
	WSABUF *wsabuf = NULL;
	char **buffer = NULL;

	bool is_read_operation = false;

	while ( true )
	{
		completion_status = GetQueuedCompletionStatus( hIOCP, &io_size, ( ULONG_PTR * )&context, ( OVERLAPPED ** )&overlapped, INFINITE );

		if ( g_shutdown_server )
		{
			break;
		}

		if ( context == NULL )
		{
			continue;
		}

		InterlockedExchange( &context->timeout, 0 );	// Reset timeout counter.

		use_ssl = ( context->ssl != NULL ? true : false );

		if ( overlapped == &( context->overlapped_read ) )
		{
			current_operation = &( context->current_operation_read );
			wsabuf = &( context->wsabuf_read );
			buffer = &( context->buffer_read );

			is_read_operation = true;
		}
		else
		{
			current_operation = &( context->current_operation_write );
			wsabuf = &( context->wsabuf_write );
			buffer = &( context->buffer_write );

			is_read_operation = false;
		}

		if ( *current_operation != IO_Accept )
		{
			bool skip_process = false;

			EnterCriticalSection( &context->shared_request_info->context_cs );

			InterlockedDecrement( &context->pending_operations );

			// Handle connection failure, or connection close.
			if ( completion_status == FALSE ||
			   ( io_size == 0 &&
				 *current_operation != IO_Connect &&
				 *current_operation != IO_ClientHandshakeReply &&
				 *current_operation != IO_ClientHandshakeResponse &&
				 /**current_operation != IO_ServerHandshakeReply &&*/
				 *current_operation != IO_ServerHandshakeResponse ) )
			{
				// Handle system timed out connections. (Should only happen with client context connections)
				if ( *current_operation == IO_Connect && cfg_retry_client_timeout )
				{
					context->timed_out = TIME_OUT_RETRY;

					// See if we have any more IP addresses to try. If not, then close the relay connection.
					if ( context->address_info != NULL && context->address_info->ai_next == NULL )
					{
						if ( context->relay_context != NULL )
						{
							context->relay_context->relay_context = NULL;

							BeginClose( context->relay_context, ( ( context->relay_context != NULL && context->relay_context->ssl != NULL ) ? IO_Shutdown : IO_Close ) );

							context->relay_context = NULL;
						}
					}
				}
				else	// Close the relay connection.
				{
					if ( context->relay_context != NULL )
					{
						context->relay_context->relay_context = NULL;

						BeginClose( context->relay_context, ( ( context->relay_context != NULL && context->relay_context->ssl != NULL ) ? IO_Shutdown : IO_Close ) );

						context->relay_context = NULL;
					}
				}

				if ( is_read_operation )
				{
					if ( !context->is_writing )
					{
						if ( context->pending_operations == 0 )
						{
							IO_OPERATION io_operation = IO_Close;

							context->current_operation_read = io_operation;
							context->current_operation_write = io_operation;
							context->next_operation_write = io_operation;
						}
						else
						{
							if ( context->socket != INVALID_SOCKET )
							{
								SOCKET s = context->socket;
								context->socket = INVALID_SOCKET;
								_shutdown( s, SD_BOTH );
								_closesocket( s );	// Saves us from having to post if there's already a pending IO operation. Should force the operation to complete.
							}

							skip_process = true;
						}
					}
					else
					{
						context->finish_writing = true;

						skip_process = true;
					}
				}
				else
				{
					context->finish_writing = true;

					context->is_writing = false;

					if ( context->pending_operations == 0 )
					{
						IO_OPERATION io_operation = IO_Close;

						context->current_operation_read = io_operation;
						context->current_operation_write = io_operation;
						context->next_operation_write = io_operation;
					}
					else
					{
						skip_process = true;
					}
				}
			}

			LeaveCriticalSection( &context->shared_request_info->context_cs );

			if ( skip_process )
			{
				continue;
			}
		}

		switch ( *current_operation )
		{
			case IO_Accept:
			{
				unsigned char proxy_type = context->proxy_type;

				SOCKET *listen_socket = NULL;
				if ( proxy_type & PROXY_TYPE_HTTP )	// Handles PROXY_TYPE_HTTP and PROXY_TYPE_HTTP_AND_HTTPS
				{
					listen_socket = &g_listen_socket;
				}
				else if ( proxy_type == PROXY_TYPE_HTTPS )
				{
					listen_socket = &g_listen_socket_s;
				}
				else
				{
					_WSASetEvent( g_hCleanupEvent[ 0 ] );

					ExitThread( 0 );
					return 0;
				}

				// Allow the accept socket to inherit the properties of the listen socket.
				// The context here is actually from listen_context->data or listen_context_s->data.
				nRet = _setsockopt( context->socket, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, ( char * )&( *listen_socket ), sizeof( *listen_socket ) );
				if ( nRet != SOCKET_ERROR )
				{
					// Create a new socket context with the inherited socket.
					SOCKET_CONTEXT *new_context = UpdateCompletionPort( context->socket, false );
					if ( new_context != NULL )
					{
						new_context->proxy_type = proxy_type;

						InterlockedIncrement( &new_context->pending_operations );

						// Accept incoming SSL/TLS connections, but not if we're going to decrypt the SSL/TLS tunnel connections.
						if ( cfg_use_ssl && !cfg_decrypt_tunnel )
						{
							new_context->current_operation_read = IO_ServerHandshakeReply;

							SSL_WSAAccept( new_context, sent );
						}
						else
						{
							sent = true;

							new_context->current_operation_read = IO_GetRequest;

							new_context->wsabuf_read.buf = new_context->buffer_read;
							new_context->wsabuf_read.len = BUFFER_SIZE;

							nRet = _WSARecv( new_context->socket, &new_context->wsabuf_read, 1, NULL, &dwFlags, &new_context->overlapped_read, NULL );
							if ( nRet == SOCKET_ERROR && ( _WSAGetLastError() != ERROR_IO_PENDING ) )
							{
								sent = false;
							}
						}

						if ( !sent )
						{
							InterlockedDecrement( &new_context->pending_operations );

							BeginClose( new_context, IO_Close );
						}
					}
					else	// Clean up the listen context.
					{
						if ( context->socket != INVALID_SOCKET )
						{
							_shutdown( context->socket, SD_BOTH );
							_closesocket( context->socket );
							context->socket = INVALID_SOCKET;
						}

						GlobalFree( context );
						context = NULL;
					}
				}
				else	// Clean up the listen context.
				{
					if ( context->socket != INVALID_SOCKET )
					{
						_shutdown( context->socket, SD_BOTH );
						_closesocket( context->socket );
						context->socket = INVALID_SOCKET;
					}

					GlobalFree( context );
					context = NULL;
				}

				// Post another outstanding AcceptEx.
				if ( ( proxy_type & PROXY_TYPE_HTTP ) && !CreateAcceptSocket( g_use_ipv6, proxy_type ) )
				{
					EnterCriticalSection( &console_cs );
					SetConsoleTextAttribute( g_hOutput, FOREGROUND_RED | FOREGROUND_INTENSITY );
					if ( proxy_type == PROXY_TYPE_HTTP_AND_HTTPS )
					{
						_wprintf( L"Unable to accept connection on HTTP and HTTPS listening socket.\r\n" );
					}
					else// if ( proxy_type == PROXY_TYPE_HTTP )
					{
						_wprintf( L"Unable to accept connection on HTTP listening socket.\r\n" );
					}
					SetConsoleTextAttribute( g_hOutput, ConsoleScreenBufferInfo.wAttributes );
					LeaveCriticalSection( &console_cs );

					_WSASetEvent( g_hCleanupEvent[ 0 ] );

					ExitThread( 0 );
					return 0;
				}

				// Post another outstanding AcceptEx.
				if ( ( proxy_type == PROXY_TYPE_HTTPS ) && !CreateAcceptSocket( g_use_ipv6_s, PROXY_TYPE_HTTPS ) )
				{
					EnterCriticalSection( &console_cs );
					SetConsoleTextAttribute( g_hOutput, FOREGROUND_RED | FOREGROUND_INTENSITY );
					_wprintf( L"Unable to accept connection on HTTPS listening socket.\r\n" );
					SetConsoleTextAttribute( g_hOutput, ConsoleScreenBufferInfo.wAttributes );
					LeaveCriticalSection( &console_cs );

					_WSASetEvent( g_hCleanupEvent[ 0 ] );

					ExitThread( 0 );
					return 0;
				}
			}
			break;

			case IO_Connect:
			{
				// Allow the connect socket to inherit the properties of the previously set properties.
				// Must be done so that shutdown() will work.
				nRet = _setsockopt( context->socket, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0 );
				if ( nRet != SOCKET_ERROR )
				{
					// Do not create an SSL context for tunneled connections.
					if ( context->shared_request_info->request_type != REQUEST_TYPE_CONNECT && context->shared_request_info->url_info.protocol == PROTOCOL_HTTPS )
					{
						DWORD protocol = 0;
						switch ( cfg_protocol )
						{
							case 4:	protocol |= SP_PROT_TLS1_2_CLIENT;
							case 3:	protocol |= SP_PROT_TLS1_1_CLIENT;
							case 2:	protocol |= SP_PROT_TLS1_CLIENT;
							case 1:	protocol |= SP_PROT_SSL3_CLIENT;
							case 0:	{ if ( cfg_protocol < 4 ) { protocol |= SP_PROT_SSL2_CLIENT; } }
						}

						SSL *ssl = SSL_new( protocol, false );
						if ( ssl == NULL )
						{
							BeginClose( context->relay_context, ( ( context->relay_context != NULL && context->relay_context->ssl != NULL ) ? IO_Shutdown : IO_Close ) );

							// Failed to create an SSL context. Close the connection.
							CleanupConnection( context );
							context = NULL;

							break;
						}

						ssl->s = context->socket;

						context->ssl = ssl;

						/////////////////////

						InterlockedIncrement( &context->pending_operations );

						context->current_operation_read = IO_ClientHandshakeResponse;
						context->next_operation_write = IO_ClientHandshakeResponse;

						scRet = SSL_WSAConnect( context, context->shared_request_info->url_info.host, sent );
						if ( /*scRet == SEC_E_INTERNAL_ERROR ||*/ !sent )
						{
							BeginClose( context->relay_context, ( ( context->relay_context != NULL && context->relay_context->ssl != NULL ) ? IO_Shutdown : IO_Close ) );

							InterlockedDecrement( &context->pending_operations );

							//BeginClose( context, IO_Shutdown );
							BeginClose( context, IO_Close );
						}
					}
					else	// HTTP and SSL/TLS tunnels
					{
						EnterCriticalSection( &context->shared_request_info->context_cs );

						// Post a read and then send the data.
						InterlockedIncrement( &context->pending_operations );

						context->current_operation_read = IO_GetRequest;

						context->wsabuf_read.buf = context->buffer_read;
						context->wsabuf_read.len = BUFFER_SIZE;

						context->do_read = true;

						context->is_reading = true;

						nRet = _WSARecv( context->socket, &context->wsabuf_read, 1, NULL, &dwFlags, &context->overlapped_read, NULL );
						if ( nRet == SOCKET_ERROR && ( _WSAGetLastError() != ERROR_IO_PENDING ) )
						{
							BeginClose( context->relay_context, ( ( context->relay_context != NULL && context->relay_context->ssl != NULL ) ? IO_Shutdown : IO_Close ) );
							
							InterlockedDecrement( &context->pending_operations );

							context->do_read = false;

							context->is_reading = false;

							BeginClose( context, IO_Close );
						}
						else
						{
							InterlockedIncrement( &context->pending_operations );

							context->current_operation_write = IO_Write;
							context->next_operation_write = IO_ProcessWrite;

							context->is_writing = true;

							nRet = _WSASend( context->socket, &context->wsabuf_write, 1, NULL, 0, &context->overlapped_write, NULL );
							if ( nRet == SOCKET_ERROR && ( _WSAGetLastError() != ERROR_IO_PENDING ) )
							{
								BeginClose( context->relay_context, ( ( context->relay_context != NULL && context->relay_context->ssl != NULL ) ? IO_Shutdown : IO_Close ) );

								InterlockedDecrement( &context->pending_operations );

								context->is_writing = false;

								BeginClose( context, IO_Close );
							}
						}

						LeaveCriticalSection( &context->shared_request_info->context_cs );
					}
				}
				else
				{
					CleanupConnection( context );
					context = NULL;
				}
			}
			break;

			case IO_ClientHandshakeResponse:
			case IO_ClientHandshakeReply:
			{
				InterlockedIncrement( &context->pending_operations );

				if ( context->current_operation_read == IO_ClientHandshakeReply )
				{
					context->ssl->cbIoBuffer += io_size;

					if ( context->ssl->cbIoBuffer > 0 )
					{
						context->current_operation_read = IO_ClientHandshakeResponse;

						context->next_operation_write = IO_ClientHandshakeResponse;

						scRet = SSL_WSAConnect_Reply( context, sent );
					}
					else
					{
						scRet = SEC_E_INTERNAL_ERROR;
					}
				}
				else
				{
					context->current_operation_read = IO_ClientHandshakeReply;

					scRet = SSL_WSAConnect_Response( context, sent );
				}

				if ( scRet == SEC_E_OK )
				{
					if ( !sent )
					{
						InterlockedDecrement( &context->pending_operations );
					}

					EnterCriticalSection( &context->shared_request_info->context_cs );

					// Post a read and then send the data.
					InterlockedIncrement( &context->pending_operations );

					context->current_operation_read = IO_GetRequest;

					context->wsabuf_read.buf = context->buffer_read;
					context->wsabuf_read.len = BUFFER_SIZE;

					context->do_read = true;

					context->is_reading = true;

					/*scRet =*/ SSL_WSARecv( context, sent );
					if ( /*scRet != SEC_E_OK*/ !sent )
					{
						BeginClose( context->relay_context, ( ( context->relay_context != NULL && context->relay_context->ssl != NULL ) ? IO_Shutdown : IO_Close ) );

						context->do_read = false;

						context->is_reading = false;

						context->current_operation_read = IO_Shutdown;

						PostQueuedCompletionStatus( hIOCP, 0, ( ULONG_PTR )context, &context->overlapped_read );
					}
					else
					{
						context->wsabuf_write = context->temp_wsabuf_write;	// Unmangled request.

						InterlockedIncrement( &context->pending_operations );

						context->next_operation_write = IO_ProcessWrite;

						context->is_writing = true;

						/*scRet =*/ SSL_WSASend( context, &context->wsabuf_write, sent );
						if ( /*scRet != SEC_E_OK ||*/ !sent )
						{
							BeginClose( context->relay_context, ( ( context->relay_context != NULL && context->relay_context->ssl != NULL ) ? IO_Shutdown : IO_Close ) );

							context->is_writing = false;
							
							context->current_operation_read = IO_Shutdown;

							PostQueuedCompletionStatus( hIOCP, 0, ( ULONG_PTR )context, &context->overlapped_read );
						}
					}

					LeaveCriticalSection( &context->shared_request_info->context_cs );
				}
				else if ( scRet != SEC_I_CONTINUE_NEEDED && scRet != SEC_E_INCOMPLETE_MESSAGE && scRet != SEC_I_INCOMPLETE_CREDENTIALS )
				{
					// Have seen SEC_E_ILLEGAL_MESSAGE (for a bad target name in InitializeSecurityContext), SEC_E_BUFFER_TOO_SMALL, and SEC_E_MESSAGE_ALTERED.

					if ( !sent )
					{
						InterlockedDecrement( &context->pending_operations );
					}

					BeginClose( context->relay_context, ( ( context->relay_context != NULL && context->relay_context->ssl != NULL ) ? IO_Shutdown : IO_Close ) );

					InterlockedIncrement( &context->pending_operations );

					context->current_operation_read = IO_Close;

					PostQueuedCompletionStatus( hIOCP, 0, ( ULONG_PTR )context, &( context->overlapped_read ) );
				}
			}
			break;

			case IO_ServerHandshakeResponse:
			case IO_ServerHandshakeReply:
			{
				// We process data from the client and write our reply.
				InterlockedIncrement( &context->pending_operations );

				if ( context->current_operation_read == IO_ServerHandshakeReply )
				{
					context->ssl->cbIoBuffer += io_size;

					context->current_operation_read = IO_ServerHandshakeResponse;

					context->next_operation_write = IO_ServerHandshakeResponse;

					scRet = SSL_WSAAccept_Reply( context, sent );
				}
				else
				{
					context->current_operation_read = IO_ServerHandshakeReply;

					scRet = SSL_WSAAccept_Response( context, sent );
				}

				if ( !sent )
				{
					InterlockedDecrement( &context->pending_operations );
				}

				if ( scRet == SEC_E_OK )	// If true, then no send was made.
				{
					InterlockedIncrement( &context->pending_operations );

					context->current_operation_read = IO_GetRequest;

					if ( context->ssl->cbIoBuffer > 0 )
					{
						// The request was sent with the handshake.
						PostQueuedCompletionStatus( hIOCP, context->ssl->cbIoBuffer, ( ULONG_PTR )context, &context->overlapped_read );
					}
					else
					{
						context->wsabuf_read.buf = context->buffer_read;
						context->wsabuf_read.len = BUFFER_SIZE;

						/*scRet =*/ SSL_WSARecv( context, sent );
						if ( /*scRet != SEC_E_OK ||*/ !sent )
						{
							context->current_operation_read = IO_Shutdown;

							PostQueuedCompletionStatus( hIOCP, 0, ( ULONG_PTR )context, &context->overlapped_read );
						}
					}
				}
				else if ( scRet == SEC_E_INCOMPLETE_MESSAGE && context->current_operation_read == IO_ServerHandshakeResponse )
				{
					// An SEC_E_INCOMPLETE_MESSAGE after SSL_WSAAccept_Reply can indicate that it doesn't support SSL/TLS, but sent the request as plaintext.

					InterlockedIncrement( &context->pending_operations );

					context->wsabuf_read.buf = context->buffer_read;
					context->wsabuf_read.len = BUFFER_SIZE;

					DWORD bytes_read = min( BUFFER_SIZE, context->ssl->cbIoBuffer );

					_memcpy_s( context->wsabuf_read.buf, BUFFER_SIZE, context->ssl->pbIoBuffer, bytes_read );
					context->current_operation_read = IO_GetRequest;

					SSL_free( context->ssl );
					context->ssl = NULL;

					PostQueuedCompletionStatus( hIOCP, bytes_read, ( ULONG_PTR )context, &context->overlapped_read );
				}
				else if ( scRet != SEC_I_CONTINUE_NEEDED && scRet != SEC_E_INCOMPLETE_MESSAGE && scRet != SEC_I_INCOMPLETE_CREDENTIALS )	// Stop handshake and close the connection.
				{
					BeginClose( context, IO_Close );
				}
			}
			break;

			case IO_GetRequest:
			{
				bool get_extra_data = false;
				int status = 0;

				bool exit_case = false;

				DWORD bytes_decrypted = io_size;
				DWORD total_bytes_decrypted = bytes_decrypted;

				// We'll continue to decode our data if there's unprocessed data that has already been decrypted.
				do
				{
					if ( use_ssl )
					{
						// We'll need to decrypt any remaining undecrypted data as well as copy the decrypted data to our wsabuf.
						if ( get_extra_data )
						{
							bytes_decrypted = context->ssl->cbIoBuffer;
						}

						scRet = DecryptRecv( context, bytes_decrypted, get_extra_data );
					}

					if ( bytes_decrypted > 0 )
					{
						total_bytes_decrypted = bytes_decrypted + ( wsabuf->buf - *buffer );

						wsabuf->buf = *buffer;
						wsabuf->len = BUFFER_SIZE;

						wsabuf->buf[ total_bytes_decrypted ] = 0;	// Sanity.


						// If we're not forwarding the connection to another proxy,
						// then we're going to need to know when the last client request has finished so that we can establish a new server connection if needed.
						if ( ( ( context->proxy_type & PROXY_TYPE_HTTP ) && !cfg_forward_connections ) ||
							 ( ( context->proxy_type & PROXY_TYPE_HTTPS ) && !cfg_forward_connections_s ) )
						{
							// If we get a new request, then reset our request info.
							if ( ( context->shared_request_info->request_type == REQUEST_TYPE_GET ||
								 ( context->shared_request_info->request_type == REQUEST_TYPE_POST && context->post_completed ) ) &&
								 context->shared_request_info->connection_steps != STEP_GET_REQUEST &&
								 context->context_type == CONTEXT_TYPE_SERVER )
							{
								context->shared_request_info->request_type = REQUEST_TYPE_UNKNOWN;
								context->shared_request_info->connection_steps = STEP_GET_REQUEST;
								context->post_completed = false;

								_memzero( &context->header_info, sizeof( HEADER_INFO ) );
							}
						}


						if ( context->shared_request_info->connection_steps == STEP_GET_REQUEST )
						{
							status = ParseHTTPRequest( context, wsabuf->buf, total_bytes_decrypted );
						}
						else
						{
							// If we've already connected to the remote server, then relay the data.
							if ( context->shared_request_info->connection_steps == STEP_CONNECT_TO_SERVER )	// For CONNECT
							{
								context->shared_request_info->connection_steps = STEP_GOT_REQUEST;
							}
							else if ( context->shared_request_info->connection_steps == STEP_GOT_REQUEST )
							{
								/*if ( context->shared_request_info->request_type == REQUEST_TYPE_GET )
								{
									GetHeaderInfo( context, wsabuf->buf );
								}*/

								context->shared_request_info->connection_steps = STEP_RELAY_DATA;
							}

							wsabuf->len = total_bytes_decrypted;
						}
					}
					else if ( use_ssl )
					{
						if ( scRet == SEC_E_INCOMPLETE_MESSAGE )
						{
							InterlockedIncrement( &context->pending_operations );

							//wsabuf->buf += bytes_decrypted;
							//wsabuf->len -= bytes_decrypted;

							SSL_WSARecv( context, sent );
							if ( !sent )
							{
								InterlockedDecrement( &context->pending_operations );
							}
							else
							{
								exit_case = true;

								break;
							}
						}

						// SEC_I_CONTEXT_EXPIRED may occur here.

						status = -1;
					}

					// Process the data above first before we shutdown.
					if ( status == -1 )
					{
						BeginClose( context->relay_context, ( ( context->relay_context != NULL && context->relay_context->ssl != NULL ) ? IO_Shutdown : IO_Close ) );
						BeginClose( context, ( use_ssl ? IO_Shutdown : IO_Close ) );

						exit_case = true;

						break;
					}
				}
				while ( get_extra_data );

				if ( exit_case )
				{
					break;
				}

				// Read more data.
				if ( status == 1 )	// context->wsabuf_read will have been set if we need more data. Don't reset it.
				{
					*current_operation = IO_GetRequest;

					if ( !TryReceive( context ) )
					{
						BeginClose( context->relay_context, ( ( context->relay_context != NULL && context->relay_context->ssl != NULL ) ? IO_Shutdown : IO_Close ) );
						BeginClose( context, ( use_ssl ? IO_Shutdown : IO_Close ) );
					}
				}
				else
				{
					EnterCriticalSection( &context->shared_request_info->context_cs );

					if ( HandleRequest( context ) == -1 )
					{
						BeginClose( context->relay_context, ( ( context->relay_context != NULL && context->relay_context->ssl != NULL ) ? IO_Shutdown : IO_Close ) );
						BeginClose( context, ( use_ssl ? IO_Shutdown : IO_Close ) );
					}

					LeaveCriticalSection( &context->shared_request_info->context_cs );
				}
			}
			break;

			case IO_Write:
			{
				// We need this in a critical section because any completed read operation that fails while this section is reached could cause a race condition.
				EnterCriticalSection( &context->shared_request_info->context_cs );

				// Make sure we've sent everything before we do anything else.
				if ( io_size < context->wsabuf_write.len )
				{
					InterlockedIncrement( &context->pending_operations );

					context->wsabuf_write.buf += io_size;
					context->wsabuf_write.len -= io_size;

					// We do a regular WSASend here since that's what we last did in SSL_WSASend.
					nRet = _WSASend( context->socket, &context->wsabuf_write, 1, NULL, 0, &context->overlapped_write, NULL );
					if ( nRet == SOCKET_ERROR && ( _WSAGetLastError() != ERROR_IO_PENDING ) )
					{
						context->is_writing = false;

						BeginClose( context->relay_context, ( ( context->relay_context != NULL && context->relay_context->ssl != NULL ) ? IO_Shutdown : IO_Close ) );

						context->current_operation_read = IO_Close;
						context->current_operation_write = IO_Close;
						context->next_operation_write = IO_Close;

						PostQueuedCompletionStatus( hIOCP, 0, ( ULONG_PTR )context, &context->overlapped_read );
					}
				}
				else	// All the data that we wanted to send has been sent.
				{
					context->current_operation_write = context->next_operation_write;

					context->is_writing = false;

					if ( context->current_operation_write == IO_ProcessWrite )
					{
						if ( !context->finish_writing )
						{
							// If there's data waiting to be written, do the request again.
							if ( context->do_write )
							{
								if ( HandleRequest( context->relay_context ) == -1 )
								{
									BeginClose( context->relay_context, ( ( context->relay_context != NULL && context->relay_context->ssl != NULL ) ? IO_Shutdown : IO_Close ) );
									BeginClose( context, ( use_ssl ? IO_Shutdown : IO_Close ) );
								}
							}
						}
						else	// The client or server shutdown/closed its connection and its relay connection was still writing. We'll shutdown/close the relay connection now.
						{
							context->finish_writing = false;	// Reset so we can shutdown/close properly.

							BeginClose( context, ( use_ssl ? IO_Shutdown : IO_Close ) );
						}
					}
					else
					{
						context->wsabuf_write.buf = context->buffer_write;
						context->wsabuf_write.len = BUFFER_SIZE;

						/*if ( context->current_operation_write == IO_ServerHandshakeResponse ||
							 context->current_operation_write == IO_ClientHandshakeResponse ||
							 context->current_operation_write == IO_Shutdown ||
							 context->current_operation_write == IO_Close ||
							 context->current_operation_write == IO_ForceClose )
						{
							InterlockedIncrement( &context->pending_operations );

							PostQueuedCompletionStatus( hIOCP, 0, ( ULONG_PTR )context, &context->overlapped_read );
						}*/

						if ( context->current_operation_write == IO_ServerHandshakeResponse ||
							 context->current_operation_write == IO_ClientHandshakeResponse ||
							 context->current_operation_write == IO_Shutdown ||
							 context->current_operation_write == IO_Close )
						{
							InterlockedIncrement( &context->pending_operations );

							context->current_operation_read = context->current_operation_write;

							PostQueuedCompletionStatus( hIOCP, 0, ( ULONG_PTR )context, &context->overlapped_read );
						}
					}
				}

				LeaveCriticalSection( &context->shared_request_info->context_cs );
			}
			break;

			case IO_Shutdown:
			{
				context->next_operation_write = IO_Close;

				InterlockedIncrement( &context->pending_operations );

				context->wsabuf_write.buf = context->buffer_write;
				context->wsabuf_write.len = BUFFER_SIZE;

				/*scRet = */SSL_WSAShutdown( context, sent );

				// We'll fall through the IO_Shutdown to IO_Close.
				if ( !sent )
				{
					InterlockedDecrement( &context->pending_operations );

					context->current_operation_read = IO_Close;
					context->current_operation_write = IO_Close;
				}
				else	// The shutdown sent data. IO_Close will be called in IO_Write.
				{
					break;
				}

				/*if ( scRet != SEC_E_OK )
				{
					InterlockedIncrement( &context->pending_operations );

					context->current_operation_read = IO_Close;
					
					PostQueuedCompletionStatus( hIOCP, 0, ( ULONG_PTR )context, &context->overlapped_read );
				}*/
			}

			case IO_Close:
			{
				EnterCriticalSection( &context->shared_request_info->context_cs );

				if ( context->pending_operations > 0 )
				{
					if ( context->socket != INVALID_SOCKET )
					{
						SOCKET s = context->socket;
						context->socket = INVALID_SOCKET;
						_shutdown( s, SD_BOTH );
						_closesocket( s );	// Saves us from having to post if there's already a pending IO operation. Should force the operation to complete.
					}

					LeaveCriticalSection( &context->shared_request_info->context_cs );

					break;
				}

				LeaveCriticalSection( &context->shared_request_info->context_cs );

				// Attempt to connect to a new address if we time out.
				if ( cfg_retry_client_timeout &&
					 context->context_type == CONTEXT_TYPE_CLIENT &&
					 context->timed_out == TIME_OUT_RETRY &&
					 context->address_info != NULL &&
					 context->address_info->ai_next != NULL &&
					 context->relay_context != NULL )
				{
					if ( context->socket != INVALID_SOCKET )
					{
						_shutdown( context->socket, SD_BOTH );
						_closesocket( context->socket );
						context->socket = INVALID_SOCKET;
					}

					if ( context->ssl != NULL )
					{
						SSL_free( context->ssl );
						context->ssl = NULL;
					}

					addrinfoW *old_address_info = context->address_info;
					context->address_info = context->address_info->ai_next;
					old_address_info->ai_next = NULL;

					_FreeAddrInfoW( old_address_info );

					context->timed_out = TIME_OUT_FALSE;

					if ( g_show_output )
					{
						if ( context->address_info != NULL )
						{
							EnterCriticalSection( &console_cs );
							char cs_ip[ 64 ];
							_memzero( cs_ip, 64 );
							DWORD cs_ip_length = 64;

							if ( !_WSAAddressToStringA( context->address_info->ai_addr, context->address_info->ai_addrlen, NULL, cs_ip, &cs_ip_length ) )
							{
								_printf( "Client connection timed out. Retrying with: %s://%s:%lu/ (%s)\r\n",
										( context->shared_request_info->url_info.protocol == PROTOCOL_HTTP ? "http" : ( context->shared_request_info->url_info.protocol == PROTOCOL_HTTPS ? "https" : "unknown" ) ),
										  SAFESTRA( context->shared_request_info->url_info.host ),
										  context->shared_request_info->url_info.port,
										  cs_ip );
							}
							LeaveCriticalSection( &console_cs );
						}
					}

					context->finish_writing = false;	// Reset so we can forcefully close retried connections.

					//context->is_writing = true;

					// Connect to the remote server.
					if ( !CreateConnection( context, context->shared_request_info->url_info.host, context->shared_request_info->url_info.port ) )
					{
						//context->is_writing = false;

						context->timed_out = TIME_OUT_TRUE;
					}
					else
					{
						break;
					}
				}

				if ( g_show_output )
				{
					EnterCriticalSection( &console_cs );

					char cs_ip[ 64 ];
					_memzero( cs_ip, 64 );
					DWORD cs_ip_length = 64;

					if ( context->context_type == CONTEXT_TYPE_CLIENT )
					{
						if ( context->address_info != NULL )
						{
							if ( !_WSAAddressToStringA( context->address_info->ai_addr, context->address_info->ai_addrlen, NULL, cs_ip, &cs_ip_length ) )
							{
								_printf( "Client connection %s: %s://%s:%lu/ (%s)\r\n",
										( context->timed_out == TIME_OUT_TRUE ? "timed out" : "closed" ),
										( context->shared_request_info->url_info.protocol == PROTOCOL_HTTP ? "http" : ( context->shared_request_info->url_info.protocol == PROTOCOL_HTTPS ? "https" : "unknown" ) ),
										  SAFESTRA( context->shared_request_info->url_info.host ),
										  context->shared_request_info->url_info.port,
										  cs_ip );
							}
						}
						else
						{
							_printf( "Client connection failed: %s://%s:%lu/\r\n",
										( context->shared_request_info->url_info.protocol == PROTOCOL_HTTP ? "http" : ( context->shared_request_info->url_info.protocol == PROTOCOL_HTTPS ? "https" : "unknown" ) ),
										  SAFESTRA( context->shared_request_info->url_info.host ),
										  context->shared_request_info->url_info.port );
						}
					}
					else
					{
						if ( context->address_info != NULL )
						{
							if ( !_WSAAddressToStringA( context->address_info->ai_addr, context->address_info->ai_addrlen, NULL, cs_ip, &cs_ip_length ) )
							{
								wchar_t cs_host[ NI_MAXHOST ];
								_memzero( cs_host, sizeof( wchar_t ) * NI_MAXHOST );
								_GetNameInfoW( context->address_info->ai_addr, context->address_info->ai_addrlen, cs_host, NI_MAXHOST, NULL, 0, 0 );

								SetConsoleTextAttribute( g_hOutput, FOREGROUND_INTENSITY );
								_wprintf( L"Server connection %s: %S (%s)\r\n", ( context->timed_out == TIME_OUT_TRUE ? L"timed out" : L"closed" ), cs_ip, ( cs_host[ 0 ] != NULL ? cs_host : L"UNKNOWN HOST" ) );
								SetConsoleTextAttribute( g_hOutput, ConsoleScreenBufferInfo.wAttributes );
							}
						}
						else
						{
							_printf( "Server connection failed\r\n" );
						}

					}

					LeaveCriticalSection( &console_cs );
				}

				CleanupConnection( context );
			}
			break;
		}
	}

	ExitThread( 0 );
	return 0;
}

SOCKET_CONTEXT *CreateSocketContext()
{
	SOCKET_CONTEXT *context = ( SOCKET_CONTEXT * )GlobalAlloc( GPTR, sizeof( SOCKET_CONTEXT ) );
	if ( context )
	{
		context->buffer_read = ( CHAR * )GlobalAlloc( GPTR, BUFFER_SIZE + 1 );

		context->wsabuf_read.buf = context->buffer_read;
		context->wsabuf_read.len = BUFFER_SIZE;

		context->buffer_write = ( CHAR * )GlobalAlloc( GPTR, BUFFER_SIZE + 1 );

		context->wsabuf_write.buf = context->buffer_write;
		context->wsabuf_write.len = BUFFER_SIZE;

		context->socket = INVALID_SOCKET;
	}

	return context;
}

bool CreateConnection( SOCKET_CONTEXT *context, char *host, unsigned short port )
{
	bool status = false;

	if ( context == NULL || host == NULL )
	{
		return status;
	}

	int nRet = 0;

	addrinfoW hints;

	bool use_ipv6 = false;

	wchar_t *whost = NULL, *t_whost = NULL;
	wchar_t wport[ 6 ];

	if ( context->address_info == NULL )
	{
		// Resolve the remote host.
		_memzero( &hints, sizeof( addrinfoW ) );
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_IP;

		// If the proxy type is PROXY_TYPE_HTTP_AND_HTTPS, then we need to distinguish if it this context is for HTTP or HTTPS.
		// PROXY_TYPE_IS_HTTPS will have been set in ParseHTTPRequest for all HTTPS connections.
		if ( ( ( context->proxy_type & PROXY_TYPE_HTTP ) && !( context->proxy_type & PROXY_TYPE_IS_HTTPS ) && cfg_forward_connections ) ||
			 ( ( context->proxy_type & PROXY_TYPE_HTTPS ) && cfg_forward_connections_s ) )
		{
			if ( ( context->proxy_type & PROXY_TYPE_HTTP ) && !( context->proxy_type & PROXY_TYPE_IS_HTTPS ) )
			{
				__snwprintf( wport, 6, L"%hu", cfg_forward_port );

				whost = ( g_forward_punycode_hostname_ip_address != NULL ? g_forward_punycode_hostname_ip_address : cfg_forward_hostname_ip_address );
			}
			else// if ( context->proxy_type & PROXY_TYPE_HTTPS )
			{
				__snwprintf( wport, 6, L"%hu", cfg_forward_port_s );

				whost = ( g_forward_punycode_hostname_ip_address_s != NULL ? g_forward_punycode_hostname_ip_address_s : cfg_forward_hostname_ip_address_s );
			}
		}
		else
		{
			__snwprintf( wport, 6, L"%hu", port );

			int whost_length = MultiByteToWideChar( CP_UTF8, 0, host, -1, NULL, 0 );	// Include the NULL terminator.
			whost = ( wchar_t * )GlobalAlloc( GMEM_FIXED, sizeof( wchar_t ) * whost_length );
			MultiByteToWideChar( CP_UTF8, 0, host, -1, whost, whost_length );

			// No need to punycode the host here since it'll be the responsibility of the client that's connected to the proxy to punycode the host.

			t_whost = whost;
		}

		nRet = _GetAddrInfoW( whost, wport, &hints, &context->address_info );
		if ( nRet == WSAHOST_NOT_FOUND )
		{
			use_ipv6 = true;

			hints.ai_family = AF_INET6;	// Try IPv6
			nRet = _GetAddrInfoW( whost, wport, &hints, &context->address_info );
		}

		if ( nRet != 0 )
		{
			GlobalFree( t_whost );
			return false;
		}
		GlobalFree( t_whost );
	}

	context->socket = CreateSocket( use_ipv6 );

	g_hIOCP = CreateIoCompletionPort( ( HANDLE )context->socket, g_hIOCP, ( ULONG_PTR )context, 0 );
	if ( g_hIOCP != NULL )
	{
		if ( g_show_output )
		{
			if ( context->address_info != NULL )
			{
				EnterCriticalSection( &console_cs );
				char cs_ip[ 64 ];
				_memzero( cs_ip, 64 );
				DWORD cs_ip_length = 64;
				if ( !_WSAAddressToStringA( context->address_info->ai_addr, context->address_info->ai_addrlen, NULL, cs_ip, &cs_ip_length ) )
				{
					_printf( "Client connecting to: %s://%s:%lu/ (%s)\r\n",
							( context->shared_request_info->url_info.protocol == PROTOCOL_HTTP ? "http" : ( context->shared_request_info->url_info.protocol == PROTOCOL_HTTPS ? "https" : "unknown" ) ),
							  SAFESTRA( context->shared_request_info->url_info.host ),
							  context->shared_request_info->url_info.port,
							  cs_ip );
				}
				LeaveCriticalSection( &console_cs );
			}
		}

		// Socket must be bound before we can use it with ConnectEx.
		struct sockaddr_in ipv4_addr;
		struct sockaddr_in6 ipv6_addr;

		if ( use_ipv6 )
		{
			_memzero( &ipv6_addr, sizeof( ipv6_addr ) );
			ipv6_addr.sin6_family = AF_INET6;
			//ipv6_addr.sin6_addr = in6addr_any;	// This assignment requires the CRT, but it's all zeros anyway and it gets set by _memzero().
			//ipv6_addr.sin6_port = 0;
			nRet = _bind( context->socket, ( SOCKADDR * )&ipv6_addr, sizeof( ipv6_addr ) );
		}
		else
		{
			_memzero( &ipv4_addr, sizeof( ipv4_addr ) );
			ipv4_addr.sin_family = AF_INET;
			//ipv4_addr.sin_addr.s_addr = INADDR_ANY;
			//ipv4_addr.sin_port = 0;
			nRet = _bind( context->socket, ( SOCKADDR * )&ipv4_addr, sizeof( ipv4_addr ) );
		}

		if ( nRet != SOCKET_ERROR )
		{
			// Attempt to connect to the host.
			InterlockedIncrement( &context->pending_operations );

			context->current_operation_write = IO_Connect;

			DWORD lpdwBytesSent = 0;
			BOOL bRet = _ConnectEx( context->socket, context->address_info->ai_addr, ( int )context->address_info->ai_addrlen, NULL, 0, &lpdwBytesSent, &context->overlapped_write );
			if ( bRet == TRUE || ( _WSAGetLastError() == ERROR_IO_PENDING ) )
			{
				status = true;
			}
		}
	}

	return status;
}

bool LoadConnectEx()
{
	bool ret = false;

	DWORD bytes = 0;
	GUID connectex_guid = WSAID_CONNECTEX;

	if ( _ConnectEx == NULL )
	{
		SOCKET tmp_socket = CreateSocket();

		// Load the ConnectEx extension function from the provider for this socket.
		ret = ( _WSAIoctl( tmp_socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &connectex_guid, sizeof( connectex_guid ), &_ConnectEx, sizeof( _ConnectEx ), &bytes, NULL, NULL ) == SOCKET_ERROR ? false : true );

		_closesocket( tmp_socket );
	}
	else
	{
		ret = true;
	}

	return ret;
}

char CreateListenSocket( wchar_t *host, unsigned short port, bool &use_ipv6, unsigned char proxy_type )
{
	unsigned char ret = LA_STATUS_FAILED;
	int nRet = 0;

	DWORD bytes = 0;
	GUID acceptex_guid = WSAID_ACCEPTEX;	// GUID to Microsoft specific extensions

	struct addrinfoW hints;
	struct addrinfoW *addrlocal = NULL;

	// Resolve the interface
	_memzero( &hints, sizeof( addrinfoW ) );
	hints.ai_flags = AI_PASSIVE;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_IP;

	SOCKET *listen_socket = NULL;

	if ( proxy_type == PROXY_TYPE_HTTP )
	{
		listen_socket = &g_listen_socket;
	}
	else if ( proxy_type == PROXY_TYPE_HTTPS )
	{
		listen_socket = &g_listen_socket_s;
	}
	else
	{
		return ret;
	}

	wchar_t cport[ 6 ];
	__snwprintf( cport, 6, L"%hu", port );

	// Use Hostname or IPv4/6 Address.
	nRet = _GetAddrInfoW( host, cport, &hints, &addrlocal );
	if ( nRet == WSAHOST_NOT_FOUND )
	{
		use_ipv6 = true;

		hints.ai_family = AF_INET6;	// Try IPv6
		nRet = _GetAddrInfoW( host, cport, &hints, &addrlocal );
	}

	if ( nRet != 0 )
	{
		goto CLEANUP;
	}

	if ( addrlocal == NULL )
	{
		goto CLEANUP;
	}

	if ( proxy_type == PROXY_TYPE_HTTP )
	{
		_memcpy_s( listen_addr_data, sizeof( CHAR ) * 14, addrlocal->ai_addr->sa_data, sizeof( CHAR ) * 14 );
	}
	else// if ( proxy_type == PROXY_TYPE_HTTPS )
	{
		_memcpy_s( listen_addr_data_s, sizeof( CHAR ) * 14, addrlocal->ai_addr->sa_data, sizeof( CHAR ) * 14 );
	}

	if ( g_listen_socket != INVALID_SOCKET || g_listen_socket_s != INVALID_SOCKET )
	{
		// Compare the address and ports.
		// If they're the same, then just use one listen context.
		if ( ( _memcmp( listen_addr_data, listen_addr_data_s, sizeof( CHAR ) * 14 ) == 0 ) && cfg_port == cfg_port_s )
		{
			ret = LA_STATUS_DUPLICATE;	// In use.
			goto CLEANUP;
		}
	}

	*listen_socket = CreateSocket( use_ipv6 );
	if ( *listen_socket == INVALID_SOCKET)
	{
		goto CLEANUP;
	}

	nRet = _bind( *listen_socket, addrlocal->ai_addr, ( int )addrlocal->ai_addrlen );
	if ( nRet == SOCKET_ERROR)
	{
		goto CLEANUP;
	}

	nRet = _listen( *listen_socket, SOMAXCONN );
	if ( nRet == SOCKET_ERROR )
	{
		goto CLEANUP;
	}

	// We need only do this once.
	if ( _AcceptEx == NULL )
	{
		// Load the AcceptEx extension function from the provider.
		// It doesn't matter what socket we use so long as it's valid.
		nRet = _WSAIoctl( *listen_socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &acceptex_guid, sizeof( acceptex_guid ), &_AcceptEx, sizeof( _AcceptEx ), &bytes, NULL, NULL );
		if ( nRet == SOCKET_ERROR )
		{
			goto CLEANUP;
		}
	}

	ret = LA_STATUS_OK;

CLEANUP:

	if ( addrlocal != NULL )
	{
		_FreeAddrInfoW( addrlocal );
	}

	return ret;
}

char CreateAcceptSocket( bool use_ipv6, unsigned char proxy_type )
{
	int nRet = 0;
	DWORD dwRecvNumBytes = 0;

	SOCKET_CONTEXT **context = NULL;

	SOCKET *listen_socket = NULL;

	if ( proxy_type & PROXY_TYPE_HTTP )	// Handles PROXY_TYPE_HTTP and PROXY_TYPE_HTTP_AND_HTTPS
	{
		context = &listen_context;

		listen_socket = &g_listen_socket;
	}
	else if ( proxy_type == PROXY_TYPE_HTTPS )
	{
		context = &listen_context_s;

		listen_socket = &g_listen_socket_s;
	}
	else
	{
		return LA_STATUS_FAILED;
	}

	// The listening socket context uses the SocketAccept member to store the socket for client connection.
	if ( *context == NULL )
	{
		*context = UpdateCompletionPort( *listen_socket, true );
		if ( *context == NULL )
		{
			return LA_STATUS_FAILED;
		}

		( *context )->proxy_type = proxy_type;
	}

	// The accept socket will inherit the listen socket's properties when it completes. IPv6 doesn't actually have to be set here.
	( *context )->socket = CreateSocket( use_ipv6 );
	if ( ( *context )->socket == INVALID_SOCKET )
	{
		return LA_STATUS_FAILED;
	}

	// Accept a connection without waiting for any data. (dwReceiveDataLength = 0)
	nRet = _AcceptEx( *listen_socket, ( *context )->socket, ( LPVOID )( ( *context )->buffer_read ), 0, sizeof( SOCKADDR_STORAGE ) + 16, sizeof( SOCKADDR_STORAGE ) + 16, &dwRecvNumBytes, &( *context )->overlapped_read );
	if ( nRet == SOCKET_ERROR && ( _WSAGetLastError() != ERROR_IO_PENDING ) )
	{
		return LA_STATUS_FAILED;
	}

	return LA_STATUS_OK;
}

SOCKET_CONTEXT *UpdateCompletionPort( SOCKET socket, bool is_listen_socket )
{
	SOCKET_CONTEXT *context = CreateSocketContext();
	if ( context )
	{
		context->socket = socket;

		context->current_operation_read = IO_Accept;

		context->shared_request_info = ( REQUEST_INFO * )GlobalAlloc( GPTR, sizeof( REQUEST_INFO ) );
		context->shared_request_info->shared_count = 1;

		context->context_type = CONTEXT_TYPE_SERVER;

		InitializeCriticalSection( &context->shared_request_info->context_cs );

		if ( !is_listen_socket )
		{
			context->address_info = ( addrinfoW * )GlobalAlloc( GPTR, sizeof( addrinfoW ) );
			context->address_info->ai_addr = ( sockaddr * )GlobalAlloc( GPTR, sizeof( sockaddr ) );
			socklen_t len = sizeof( sockaddr_in );
			_getpeername( context->socket, context->address_info->ai_addr, &len );
			context->address_info->ai_addrlen = len;
		}

		if ( g_show_output )
		{
			if ( !is_listen_socket )
			{
				if ( context->address_info != NULL )
				{
					EnterCriticalSection( &console_cs );
					char cs_ip[ 64 ];
					_memzero( cs_ip, 64 );
					DWORD cs_ip_length = 64;
					if ( !_WSAAddressToStringA( context->address_info->ai_addr, context->address_info->ai_addrlen, NULL, cs_ip, &cs_ip_length ) )
					{
						SetConsoleTextAttribute( g_hOutput, FOREGROUND_INTENSITY );

						wchar_t cs_host[ NI_MAXHOST ];
						_memzero( cs_host, sizeof( wchar_t ) * NI_MAXHOST );
						_GetNameInfoW( context->address_info->ai_addr, context->address_info->ai_addrlen, cs_host, NI_MAXHOST, NULL, 0, 0 );

						_wprintf( L"Accepted server connection: %S (%s)\r\n", cs_ip, ( cs_host[ 0 ] != NULL ? cs_host : L"UNKNOWN HOST" ) );

						SetConsoleTextAttribute( g_hOutput, ConsoleScreenBufferInfo.wAttributes );
					}
					LeaveCriticalSection( &console_cs );
				}
			}
		}

		// Create an SSL/TLS object for incoming SSL/TLS connections, but not for SSL/TLS tunnel connections.
		if ( !is_listen_socket && cfg_use_ssl && !cfg_decrypt_tunnel )
		{
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
			if ( ssl == NULL )
			{
				GlobalFree( context->shared_request_info );
				GlobalFree( context->buffer_read );
				GlobalFree( context->buffer_write );
				GlobalFree( context );
				context = NULL;

				return NULL;
			}

			ssl->s = socket;

			context->ssl = ssl;
		}

		g_hIOCP = CreateIoCompletionPort( ( HANDLE )socket, g_hIOCP, ( DWORD_PTR )context, 0 );
		if ( g_hIOCP == NULL )
		{
			if ( context->ssl != NULL )
			{
				SSL_free( context->ssl );
				context->ssl = NULL;
			}

			GlobalFree( context->shared_request_info );
			GlobalFree( context->buffer_read );
			GlobalFree( context->buffer_write );
			GlobalFree( context );
			context = NULL;
		}
		else
		{
			// Add all socket contexts (except the listening one) to our linked list.
			if ( !is_listen_socket )
			{
				context->context_node.data = context;

				EnterCriticalSection( &context_list_cs );

				DLL_AddNode( &context_list, &context->context_node, -1 );

				EnableTimer( true );

				LeaveCriticalSection( &context_list_cs );
			}
		}
	}

	return context;
}

void CleanupConnection( SOCKET_CONTEXT *context )
{
	if ( context != NULL )
	{
		// Disassociate the two context objects.
		EnterCriticalSection( &context->shared_request_info->context_cs );
		if ( context->relay_context != NULL )
		{
			context->relay_context->relay_context = NULL;
			context->relay_context = NULL;
		}
		LeaveCriticalSection( &context->shared_request_info->context_cs );

		EnterCriticalSection( &context_list_cs );

		// Remove from the global download list.
		DLL_RemoveNode( &context_list, &context->context_node );

		// Turn off our timer if there are no more connections.
		if ( context_list == NULL )
		{
			EnableTimer( false );
		}

		LeaveCriticalSection( &context_list_cs );

		if ( context->socket != INVALID_SOCKET )
		{
			_shutdown( context->socket, SD_BOTH );
			_closesocket( context->socket );
			context->socket = INVALID_SOCKET;
		}

		if ( context->ssl != NULL )
		{
			SSL_free( context->ssl );
			context->ssl = NULL;
		}

		if ( context->address_info != NULL )
		{
			// For incoming server connections, we'll have allocated the addrinfoW structure ourselves.
			if ( context->context_type == CONTEXT_TYPE_SERVER )
			{
				GlobalFree( context->address_info->ai_addr );
				GlobalFree( context->address_info );
			}
			else	// Free the addrinfoW structure that was allocated by _GetAddrInfoW (client connections will have used this).
			{
				_FreeAddrInfoW( context->address_info );
			}
			context->address_info = NULL;
		}

		if ( context->shared_request_info != NULL )
		{
			EnterCriticalSection( &context->shared_request_info->context_cs );

			--context->shared_request_info->shared_count;

			LeaveCriticalSection( &context->shared_request_info->context_cs );

			if ( context->shared_request_info->shared_count == 0 )
			{
				if ( context->shared_request_info->url_info.host != NULL )
				{
					GlobalFree( context->shared_request_info->url_info.host );
					context->shared_request_info->url_info.host = NULL;
				}

				if ( context->shared_request_info->url_info.resource != NULL )
				{
					GlobalFree( context->shared_request_info->url_info.resource );
					context->shared_request_info->url_info.resource = NULL;
				}

				DeleteCriticalSection( &context->shared_request_info->context_cs );

				GlobalFree( context->shared_request_info );
				context->shared_request_info = NULL;
			}
		}

		if ( context->buffer_read != NULL )
		{
			GlobalFree( context->buffer_read );
			context->buffer_read = NULL;
		}

		if ( context->buffer_write != NULL )
		{
			GlobalFree( context->buffer_write );
			context->buffer_write = NULL;
		}

		GlobalFree( context );
	}
}

// Free all context structures in the global list of context structures.
void FreeContexts()
{
	DoublyLinkedList *context_node = context_list;
	DoublyLinkedList *del_context_node = NULL;

	while ( context_node != NULL )
	{
		del_context_node = context_node;
		context_node = context_node->next;

		CleanupConnection( ( SOCKET_CONTEXT * )del_context_node->data );
	}

	context_list = NULL;

	return;
}

void FreeListenContexts()
{
	if ( listen_context != NULL )
	{
		if ( listen_context->socket != INVALID_SOCKET )
		{
			_shutdown( listen_context->socket, SD_BOTH );
			_closesocket( listen_context->socket );
			listen_context->socket = INVALID_SOCKET;
		}

		GlobalFree( listen_context );
		listen_context = NULL;
	}

	if ( listen_context_s != NULL )
	{
		if ( listen_context_s->socket != INVALID_SOCKET )
		{
			_shutdown( listen_context_s->socket, SD_BOTH );
			_closesocket( listen_context_s->socket );
			listen_context_s->socket = INVALID_SOCKET;
		}

		GlobalFree( listen_context_s );
		listen_context_s = NULL;
	}

	return;
}
