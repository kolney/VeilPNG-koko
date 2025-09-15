// sveil_extract.c

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN  // Prevents winsock.h from being included by windows.h

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>
#include <zlib.h>
#ifdef _WIN32
#pragma comment(lib, "zlibstat.lib")
#endif

#ifdef _WIN32
#include <Shlwapi.h>  // For PathCombine
#pragma comment(lib, "Shlwapi.lib")
#endif

#include "sveil_extract.h"
#include "sveil_common.h"
#include "sveil_png_utils.h"

// Use shared encryption API
#include "encryption.h"
#include "../compat/compat.h"

// Remove Windows NTSTATUS usage on non-Windows

#define PNG_SIGNATURE_SIZE 8
#define CHUNK_HEADER_SIZE 8  // Length (4 bytes) + Type (4 bytes)
#define CHUNK_CRC_SIZE 4
#define MAGIC_NUMBER 0xDEADBEEF

// Use shared encryption API from encryption.h

int sveil_extract_data_from_png(const TCHAR* png_path, const TCHAR* output_folder, const TCHAR* password,
    TCHAR* extracted_file_name) {
    unsigned char* png_data = NULL;
    size_t png_size = 0;
    unsigned char* idat_data = NULL;
    size_t idat_size = 0;
    int result = -1;

    unsigned char* uncompressed_data = NULL;
    size_t uncompressed_size = 0;

    FILE* fp = NULL;

    // Declare and initialize pointers at the beginning
    unsigned char* encrypted_data = NULL;
    size_t encrypted_data_size = 0;

    unsigned char* decrypted_data = NULL;
    size_t decrypted_data_size = 0;

    char* filename_utf8 = NULL;
    TCHAR* filename_tchar = NULL;

    size_t pos = 0;
    int found = 0;

    // Read the PNG file into memory
    fp = _tfopen(png_path, _T("rb"));
    if (!fp) {
        set_sveil_error_message(_T("Failed to open PNG file: %s"), png_path);
        goto cleanup;
    }

    fseek(fp, 0, SEEK_END);
    png_size = ftell(fp);
    rewind(fp);
    png_data = (unsigned char*)malloc(png_size);
    if (!png_data) {
        set_sveil_error_message(_T("Memory allocation failed for PNG data."));
        fclose(fp);
        fp = NULL;
        goto cleanup;
    }
    if (fread(png_data, 1, png_size, fp) != png_size) {
        set_sveil_error_message(_T("Failed to read PNG file."));
        fclose(fp);
        fp = NULL;
        free(png_data);
        png_data = NULL;
        goto cleanup;
    }
    fclose(fp);
    fp = NULL;

    // Collect IDAT data
    if (collect_idat_chunks(png_data, png_size, &idat_data, &idat_size, NULL, NULL) != 0) {
        set_sveil_error_message(_T("Failed to collect IDAT chunks."));
        goto cleanup;
    }

    // Decompress the IDAT data
    if (uncompress_idat_data(idat_data, idat_size, &uncompressed_data, &uncompressed_size) != 0) {
        set_sveil_error_message(_T("Failed to decompress IDAT data."));
        goto cleanup;
    }

    free(png_data);
    png_data = NULL;
    free(idat_data);
    idat_data = NULL;

    // Search for the hidden data using the magic number
    while (pos + sizeof(uint32_t) <= uncompressed_size) {
        uint32_t magic_number = ntohl(*(uint32_t*)(uncompressed_data + pos));

        if (magic_number == MAGIC_NUMBER) {
            pos += sizeof(uint32_t);

            // Read encrypted data length
            if (pos + sizeof(uint32_t) > uncompressed_size) break;
            uint32_t encrypted_data_length = ntohl(*(uint32_t*)(uncompressed_data + pos));
            pos += sizeof(uint32_t);

            // Read encrypted data
            if (pos + encrypted_data_length > uncompressed_size) break;
            encrypted_data_size = encrypted_data_length;
            encrypted_data = (unsigned char*)malloc(encrypted_data_size);
            if (!encrypted_data) {
                set_sveil_error_message(_T("Memory allocation failed for encrypted data."));
                goto cleanup;
            }
            memcpy(encrypted_data, uncompressed_data + pos, encrypted_data_size);
            pos += encrypted_data_size;

            // Decrypt the data
            if (decrypt_data(encrypted_data, encrypted_data_size, password, &decrypted_data, &decrypted_data_size) != 0) {
                set_sveil_error_message(_T("Failed to decrypt data. Incorrect password or data corrupted."));
                goto cleanup;
            }

            free(encrypted_data);
            encrypted_data = NULL;

            // Parse the decrypted data to extract the filename and hidden data
            unsigned char* ptr = decrypted_data;
            size_t remaining_size = decrypted_data_size;

            // Read filename length
            if (remaining_size < sizeof(unsigned int)) {
                set_sveil_error_message(_T("Insufficient data for filename length."));
                goto cleanup;
            }
            unsigned int filename_length = 0;
            memcpy(&filename_length, ptr, sizeof(unsigned int));
            ptr += sizeof(unsigned int);
            remaining_size -= sizeof(unsigned int);

            // Read filename in UTF-8
            if (remaining_size < filename_length) {
                set_sveil_error_message(_T("Insufficient data for filename."));
                goto cleanup;
            }
            filename_utf8 = (char*)malloc(filename_length + 1); // +1 for null terminator
            if (!filename_utf8) {
                set_sveil_error_message(_T("Memory allocation failed for filename."));
                goto cleanup;
            }
            memcpy(filename_utf8, ptr, filename_length);
            filename_utf8[filename_length] = '\0'; // Null-terminate
            ptr += filename_length;
            remaining_size -= filename_length;

            // Convert filename from UTF-8 to TCHAR
#ifdef _WIN32
            int filename_tchar_length = MultiByteToWideChar(CP_UTF8, 0, filename_utf8, -1, NULL, 0);
            if (filename_tchar_length <= 0) {
                set_sveil_error_message(_T("Failed to convert filename from UTF-8."));
                goto cleanup;
            }
            filename_tchar = (TCHAR*)malloc(filename_tchar_length * sizeof(TCHAR));
            if (!filename_tchar) {
                set_sveil_error_message(_T("Memory allocation failed for filename."));
                goto cleanup;
            }
            MultiByteToWideChar(CP_UTF8, 0, filename_utf8, -1, filename_tchar, filename_tchar_length);
            free(filename_utf8);
            filename_utf8 = NULL;
#else
            filename_tchar = (TCHAR*)malloc(strlen(filename_utf8) + 1);
            if (!filename_tchar) {
                set_sveil_error_message(_T("Memory allocation failed for filename."));
                goto cleanup;
            }
            strcpy(filename_tchar, filename_utf8);
            free(filename_utf8);
            filename_utf8 = NULL;
#endif

            // The remaining data is the hidden file data
            size_t hidden_data_size = remaining_size;
            unsigned char* hidden_data = ptr;

            // Sanitize the filename to prevent directory traversal
            TCHAR* sanitized_filename = filename_tchar;
            for (TCHAR* p = filename_tchar; *p; ++p) {
                if (*p == _T('\\') || *p == _T('/')) {
                    sanitized_filename = p + 1;
                }
            }

            // Construct the full path (portable)
            TCHAR full_path[MAX_PATH];
            compat_join_path(output_folder, sanitized_filename, full_path, _countof(full_path));

            // Write the hidden data to a file
            FILE* out_fp = _tfopen(full_path, _T("wb"));
            if (!out_fp) {
                set_sveil_error_message(_T("Failed to open output file: %s"), full_path);
                goto cleanup;
            }

            if (fwrite(hidden_data, 1, hidden_data_size, out_fp) != hidden_data_size) {
                set_sveil_error_message(_T("Failed to write hidden data to output file."));
                fclose(out_fp);
                out_fp = NULL;
                goto cleanup;
            }
            fclose(out_fp);
            out_fp = NULL;

            if (extracted_file_name) {
                _tcscpy_s(extracted_file_name, MAX_PATH, full_path);
            }

            found = 1;
            break;
        }
        else {
            pos += 1; // Move to the next byte and continue searching
        }
    }

    free(uncompressed_data);
    uncompressed_data = NULL;

    if (!found) {
        set_sveil_error_message(_T("No hidden data found or incorrect password."));
        goto cleanup;
    }

    result = 0;

cleanup:
    if (fp) fclose(fp);
    if (png_data) free(png_data);
    if (idat_data) free(idat_data);
    if (uncompressed_data) free(uncompressed_data);
    if (filename_utf8) free(filename_utf8);
    if (filename_tchar) free(filename_tchar);
    if (encrypted_data) free(encrypted_data);
    if (decrypted_data) {
        SecureZeroMemory(decrypted_data, decrypted_data_size);
        free(decrypted_data);
    }

    return result;
}

// Removed Windows-only decryption helpers; using encryption.h API
