#ifndef VEILPNG_COMPAT_TCHAR_H
#define VEILPNG_COMPAT_TCHAR_H

#ifdef _WIN32
#include <tchar.h>
#else
#ifndef TCHAR
typedef char TCHAR;
#endif
#ifndef _T
#define _T(x) x
#endif
#endif

#endif // VEILPNG_COMPAT_TCHAR_H

