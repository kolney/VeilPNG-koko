// compat/compat.c

#include "compat.h"

#ifndef _WIN32
#include <string.h>
#include <sys/time.h>

void compat_secure_zero_memory(void* ptr, size_t cnt) {
    volatile unsigned char* p = (volatile unsigned char*)ptr;
    while (cnt--) {
        *p++ = 0;
    }
}

void compat_join_path(const TCHAR* dir, const TCHAR* file, TCHAR* out, size_t out_size) {
    if (!dir || !*dir) {
        snprintf(out, out_size, "%s", file ? file : "");
        return;
    }
    size_t len = strlen(dir);
    if (len > 0 && (dir[len - 1] == '/' || dir[len - 1] == '\\')) {
        snprintf(out, out_size, "%s%s", dir, file ? file : "");
    } else {
        snprintf(out, out_size, "%s/%s", dir, file ? file : "");
    }
}

unsigned long long compat_get_tick_count64(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (unsigned long long)tv.tv_sec * 1000ULL + (unsigned long long)tv.tv_usec / 1000ULL;
}

void compat_sleep_ms(unsigned int ms) {
    usleep(ms * 1000U);
}

#endif // _WIN32

