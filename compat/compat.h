// compat/compat.h

#ifndef VEILPNG_COMPAT_H
#define VEILPNG_COMPAT_H

#ifdef _WIN32
// On Windows, rely on existing headers/macros
#include <windows.h>
#include <tchar.h>
#else
// Non-Windows compatibility shims
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <limits.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>

#ifndef MAX_PATH
#define MAX_PATH 4096
#endif

typedef unsigned long long ULONGLONG;

typedef char TCHAR;
#ifndef _T
#define _T(x) x
#endif

#define _tfopen fopen
#define _tcscpy_s(dst, dstsz, src) snprintf((dst), (dstsz), "%s", (src))
#define _stprintf_s snprintf
#define _tcslen strlen
#define _tcsrchr strrchr
#define _vsntprintf_s(buf, size, trunc, fmt, args) vsnprintf((buf), (size), (fmt), (args))
#define _istupper isupper
#define _istlower islower
#define _istdigit isdigit
#define _countof(arr) (sizeof(arr) / sizeof((arr)[0]))

#define SecureZeroMemory(ptr, cnt) compat_secure_zero_memory((ptr), (cnt))

void compat_secure_zero_memory(void* ptr, size_t cnt);
void compat_join_path(const TCHAR* dir, const TCHAR* file, TCHAR* out, size_t out_size);
unsigned long long compat_get_tick_count64(void);
void compat_sleep_ms(unsigned int ms);

#endif // _WIN32

#endif // VEILPNG_COMPAT_H

