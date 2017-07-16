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

#ifndef _CONNECTION_H
#define _CONNECTION_H

#include "globals.h"
#include "ssl.h"
#include "doublylinkedlist.h"

#include <mswsock.h>

#define BUFFER_SIZE						16384	// Maximum size of an SSL record.

#define DEFAULT_PORT					80
#define DEFAULT_PORT_SECURE				443

#define REQUEST_TYPE_UNKNOWN			0
#define REQUEST_TYPE_GET				1
#define REQUEST_TYPE_POST				2
#define REQUEST_TYPE_CONNECT			3
#define REQUEST_TYPE_UNSUPPORTED		4

#define STEP_GET_REQUEST				0
#define STEP_GOT_REQUEST				1
#define STEP_RELAY_DATA					2
#define STEP_CONNECT_TO_SERVER			3
#define STEP_DENY_CONNECTION			4
#define STEP_PROXY_AUTH					5

#define CONNECTION_UNKNOWN				0
#define CONNECTION_KEEP_ALIVE			1
#define CONNECTION_CLOSE				2

#define CONTEXT_TYPE_CLIENT				0	// The connection that was made to the proxy.
#define CONTEXT_TYPE_SERVER				1	// The connection that was made from the proxy.

#define PROTOCOL_UNKNOWN				0
#define PROTOCOL_HTTP					1
#define PROTOCOL_HTTPS					2
#define PROTOCOL_RELATIVE				3

#define TIME_OUT_FALSE					0
#define TIME_OUT_TRUE					1
#define TIME_OUT_RETRY					2

#define PROXY_TYPE_UNKNOWN				0
#define PROXY_TYPE_HTTP					1
#define PROXY_TYPE_HTTPS				2
#define PROXY_TYPE_HTTP_AND_HTTPS		( PROXY_TYPE_HTTP | PROXY_TYPE_HTTPS )	// 3
#define PROXY_TYPE_IS_HTTPS				4

// For listen and accept functions
#define LA_STATUS_FAILED			   -1
#define LA_STATUS_UNKNOWN				0
#define LA_STATUS_OK					1
#define LA_STATUS_DUPLICATE				2

#define AUTH_TYPE_NONE					0
#define AUTH_TYPE_BASIC					1
#define AUTH_TYPE_DIGEST				2
#define AUTH_TYPE_UNHANDLED				3

enum IO_OPERATION
{
	IO_Accept,
	IO_Connect,
	IO_ClientHandshakeReply,
	IO_ClientHandshakeResponse,
	IO_ServerHandshakeReply,
	IO_ServerHandshakeResponse,
	IO_Shutdown,
	IO_Close,
	IO_Write,
	IO_GetRequest,
	IO_ProcessWrite,
	IO_Timeout
};

struct HEADER_INFO
{
	unsigned long long		content_sent;
	unsigned long long		content_length;
	unsigned char			chunked_ending[ 5 ];
	unsigned char			chunked_ending_size;
	bool					chunked_transfer;
};

struct URL_INFO
{
	char					*host;
	char					*resource;
	unsigned char			protocol;
	unsigned short			port;
};

struct REQUEST_INFO
{
	CRITICAL_SECTION		context_cs;

	URL_INFO				url_info;

	unsigned char			connection_steps;

	unsigned char			shared_count;

	unsigned char			request_type;
};

struct SOCKET_CONTEXT;

struct SOCKET_CONTEXT
{
	WSAOVERLAPPED			overlapped_read;
	WSAOVERLAPPED			overlapped_write;

	HEADER_INFO				header_info;

	DoublyLinkedList		context_node;			// Self reference to the context_list.

	WSABUF					wsabuf_read;
	WSABUF					wsabuf_write;
	WSABUF					temp_wsabuf_write;

	REQUEST_INFO			*shared_request_info;

	SOCKET_CONTEXT			*relay_context;

	CHAR					*buffer_read;
	CHAR					*buffer_write;

	SSL						*ssl;

	addrinfoW				*address_info;

	SOCKET					socket;

	IO_OPERATION			current_operation_read;

	IO_OPERATION			current_operation_write;
	IO_OPERATION			next_operation_write;

	volatile LONG			pending_operations;

	volatile LONG			timeout;

	unsigned char			context_type;			// 0 = Client (outgoing connections), 1 = Server (incoming connections)

	unsigned char			proxy_type;

	unsigned char			timed_out;

	bool					create_new_connection;
	bool					post_completed;

	bool					do_read;
	bool					do_write;
	bool					is_reading;
	bool					is_writing;
	bool					finish_writing;
};

SECURITY_STATUS WSAAPI SSL_WSAAccept( SOCKET_CONTEXT *context, bool &sent );
SECURITY_STATUS SSL_WSAAccept_Reply( SOCKET_CONTEXT *context, bool &sent );
SECURITY_STATUS SSL_WSAAccept_Response( SOCKET_CONTEXT *context, bool &sent );

SECURITY_STATUS SSL_WSAConnect( SOCKET_CONTEXT *context, char *host, bool &sent );
SECURITY_STATUS SSL_WSAConnect_Response( SOCKET_CONTEXT *context, bool &sent );
SECURITY_STATUS SSL_WSAConnect_Reply( SOCKET_CONTEXT *context, bool &sent );

SECURITY_STATUS WSAAPI SSL_WSASend( SOCKET_CONTEXT *context, WSABUF *send_buf, bool &sent );
SECURITY_STATUS WSAAPI SSL_WSARecv( SOCKET_CONTEXT *context, bool &sent );

SECURITY_STATUS SSL_WSARecv_Decrypt( SSL *ssl, LPWSABUF lpBuffers, DWORD &lpNumberOfBytesDecrypted );

SECURITY_STATUS SSL_WSAShutdown( SOCKET_CONTEXT *context, bool &sent );

DWORD WINAPI IOCPServer( LPVOID pArgs );
DWORD WINAPI IOCPConnection( LPVOID WorkThreadContext );

SOCKET_CONTEXT *CreateSocketContext();
SOCKET_CONTEXT *UpdateCompletionPort( SOCKET socket, bool is_listen_socket );
bool CreateConnection( SOCKET_CONTEXT *context, char *host, unsigned short port );
bool LoadConnectEx();
char CreateListenSocket( wchar_t *host, unsigned short port, bool &use_ipv6, unsigned char proxy_type );
char CreateAcceptSocket( bool use_ipv6, unsigned char proxy_type );
void CleanupConnection( SOCKET_CONTEXT *context );

bool TrySend( SOCKET_CONTEXT *context );
bool TryReceive( SOCKET_CONTEXT *context );

void BeginClose( SOCKET_CONTEXT *context, IO_OPERATION io_operation );

SOCKET CreateSocket( bool IPv6 = false );

void EnableTimer( bool timer_state );

extern HANDLE g_hIOCP;

extern bool g_shutdown_server;
extern bool g_restart_server;

extern WSAEVENT g_hCleanupEvent[ 1 ];

extern CRITICAL_SECTION context_list_cs;		// Guard access to the global context list.

extern DoublyLinkedList *context_list;

#endif
