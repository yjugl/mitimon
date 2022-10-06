#ifndef WINKRABS_H
#define WINKRABS_H

// Bad things happen if including windows.h before krabs.hpp,
// using this file helps make sure this cannot happen.
#include <krabs.hpp>
#include <windows.h>

#include <fileapi.h>
#include <processenv.h>
#include <processthreadsapi.h>
#include <winerror.h>

#include <DbgHelp.h>

#pragma comment(lib, "dbghelp.lib")

#endif // WINKRABS_H
