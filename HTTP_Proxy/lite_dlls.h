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

#ifndef _LITE_DLLS_H
#define _LITE_DLLS_H

#define STRICT
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#define VALIDATE_FUNCTION_POINTER( ret ){ if ( ret == NULL ){ return false; } }

HMODULE LoadLibraryDEMW( LPCWSTR lpLibFileName );
void *SetFunctionPointer( HMODULE &library, void **function_pointer, char *function_name );

#endif
