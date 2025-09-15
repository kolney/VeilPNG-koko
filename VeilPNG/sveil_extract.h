// sveil_extract.h

#ifndef SVEIL_EXTRACT_H
#define SVEIL_EXTRACT_H

#ifdef _WIN32
#include <tchar.h>
#else
#include "../compat/tchar.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

	int sveil_extract_data_from_png(const TCHAR* png_path, const TCHAR* output_folder, const TCHAR* password, TCHAR* extracted_file_name);

#ifdef __cplusplus
}
#endif

#endif // SVEIL_EXTRACT_H
