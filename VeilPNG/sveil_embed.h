#ifndef SVEIL_EMBED_H
#define SVEIL_EMBED_H

#ifdef _WIN32
#include <tchar.h>
#else
#include "../compat/tchar.h"
#endif

int sveil_embed_data_in_png(const TCHAR* png_path, const TCHAR* data_path, const TCHAR* output_path, const TCHAR* password);
const TCHAR* get_sveil_error_message(void);

#endif // SVEIL_EMBED_H
