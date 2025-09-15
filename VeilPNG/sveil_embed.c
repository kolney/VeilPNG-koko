// sveil_embed.c

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <time.h>
#pragma comment(lib, "ws2_32.lib")
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tchar.h>
#include <zlib.h>
#include "../compat/compat.h"
#ifdef _WIN32
#pragma comment(lib, "zlibstat.lib")
#endif

#include "sveil_embed.h"
#include "sveil_common.h"
#include "sveil_png_utils.h"

#include "encryption.h"
#include "../compat/compat.h"

// Remove Windows NTSTATUS macros on non-Windows

#define PNG_SIGNATURE_SIZE 8
#define CHUNK_HEADER_SIZE 8  // Length (4 bytes) + Type (4 bytes)
#define CHUNK_CRC_SIZE 4
#define MAGIC_NUMBER 0xDEADBEEF

// Use shared encryption API from encryption.h

int sveil_embed_data_in_png(const TCHAR* png_path, const TCHAR* data_path, const TCHAR* output_path, const TCHAR* password) {
    unsigned char* png_data = NULL;
    size_t png_size = 0;
    unsigned char* idat_data = NULL;
    size_t idat_size = 0;
    size_t idat_pos = 0;
    size_t idat_total_length = 0;
    int result = -1;

    unsigned char* image_data = NULL;
    size_t image_data_size = 0;
    unsigned char* combined_data = NULL;
    size_t combined_data_size = 0;
    unsigned char* new_idat_data = NULL;
    size_t new_idat_size = 0;

    unsigned char* data_buffer = NULL;
    size_t data_size = 0;

    FILE* fp = NULL;
    FILE* data_fp = NULL;

    // Seed the random number generator
    srand((unsigned int)time(NULL));

    // Read the PNG file into memory
    fp = _tfopen(png_path, _T("rb"));
    if (!fp) {
        set_sveil_error_message(_T("Failed to open PNG file."));
        goto cleanup;
    }
    fseek(fp, 0, SEEK_END);
    png_size = ftell(fp);
    rewind(fp);
    png_data = (unsigned char*)malloc(png_size);
    if (!png_data) {
        set_sveil_error_message(_T("Memory allocation failed for PNG data."));
        fclose(fp);
        goto cleanup;
    }
    if (fread(png_data, 1, png_size, fp) != png_size) {
        set_sveil_error_message(_T("Failed to read PNG file."));
        fclose(fp);
        goto cleanup;
    }
    fclose(fp);
    fp = NULL;

    // Verify PNG signature
    if (png_size < PNG_SIGNATURE_SIZE || memcmp(png_data, "\x89PNG\r\n\x1a\n", PNG_SIGNATURE_SIZE) != 0) {
        set_sveil_error_message(_T("Invalid PNG file."));
        goto cleanup;
    }

    // Collect IDAT data
    if (collect_idat_chunks(png_data, png_size, &idat_data, &idat_size, &idat_pos, &idat_total_length) != 0) {
        set_sveil_error_message(_T("Failed to collect IDAT chunks."));
        goto cleanup;
    }

    // Decompress IDAT data
    if (uncompress_idat_data(idat_data, idat_size, &image_data, &image_data_size) != 0) {
        set_sveil_error_message(_T("Failed to decompress IDAT data."));
        goto cleanup;
    }

    // Read the data file to be embedded
    data_fp = _tfopen(data_path, _T("rb"));
    if (!data_fp) {
        set_sveil_error_message(_T("Failed to open data file."));
        goto cleanup;
    }
    fseek(data_fp, 0, SEEK_END);
    data_size = ftell(data_fp);
    rewind(data_fp);
    data_buffer = (unsigned char*)malloc(data_size);
    if (!data_buffer) {
        set_sveil_error_message(_T("Memory allocation failed for data buffer."));
        fclose(data_fp);
        goto cleanup;
    }
    if (fread(data_buffer, 1, data_size, data_fp) != data_size) {
        set_sveil_error_message(_T("Failed to read data file."));
        fclose(data_fp);
        goto cleanup;
    }
    fclose(data_fp);
    data_fp = NULL;

    // Get the filename from the data_path
    const TCHAR* filename = _tcsrchr(data_path, _T('\\'));
    if (!filename) {
        filename = _tcsrchr(data_path, _T('/'));
    }
    if (!filename) {
        filename = data_path;
    }
    else {
        filename++; // Skip the path separator
    }

    // Convert filename to UTF-8
    int filename_utf8_length = 0;
    char* filename_utf8 = NULL;
#ifdef _WIN32
    filename_utf8_length = WideCharToMultiByte(CP_UTF8, 0, filename, -1, NULL, 0, NULL, NULL);
    if (filename_utf8_length <= 0) {
        set_sveil_error_message(_T("Failed to convert filename to UTF-8."));
        goto cleanup;
    }
    filename_utf8 = (char*)malloc(filename_utf8_length);
    if (!filename_utf8) {
        set_sveil_error_message(_T("Memory allocation failed for filename."));
        goto cleanup;
    }
    WideCharToMultiByte(CP_UTF8, 0, filename, -1, filename_utf8, filename_utf8_length, NULL, NULL);
    filename_utf8_length--; // Exclude null terminator
#else
    filename_utf8_length = (int)strlen(filename);
    filename_utf8 = (char*)malloc(filename_utf8_length + 1);
    if (!filename_utf8) {
        set_sveil_error_message(_T("Memory allocation failed for filename."));
        goto cleanup;
    }
    memcpy(filename_utf8, filename, filename_utf8_length);
    filename_utf8[filename_utf8_length] = '\0';
#endif

    // Prepare the combined data buffer: [filename_length][filename][data]
    unsigned int filename_length = (unsigned int)filename_utf8_length;
    size_t plaintext_size = sizeof(unsigned int) + filename_length + data_size;
    unsigned char* plaintext = (unsigned char*)malloc(plaintext_size);
    if (!plaintext) {
        set_sveil_error_message(_T("Memory allocation failed for plaintext."));
        free(filename_utf8);
        goto cleanup;
    }

    unsigned char* ptr = plaintext;
    memcpy(ptr, &filename_length, sizeof(unsigned int));
    ptr += sizeof(unsigned int);
    memcpy(ptr, filename_utf8, filename_length);
    ptr += filename_length;
    memcpy(ptr, data_buffer, data_size);

    free(filename_utf8);
    free(data_buffer);
    data_buffer = NULL;

    // Encrypt the combined data using AES-GCM
    unsigned char* encrypted_data = NULL;
    size_t encrypted_size = 0;
    if (encrypt_data((unsigned char*)plaintext, plaintext_size, password, &encrypted_data, &encrypted_size) != 0) {
        set_sveil_error_message(_T("Failed to encrypt data."));
        free(plaintext);
        goto cleanup;
    }
    free(plaintext);

    // Append magic number, encrypted data length, and encrypted data to the image data
    uint32_t magic_number = htonl(MAGIC_NUMBER);
    uint32_t encrypted_data_length = htonl((uint32_t)encrypted_size);

    combined_data_size = image_data_size + sizeof(uint32_t) * 2 + encrypted_size;
    combined_data = (unsigned char*)malloc(combined_data_size);
    if (!combined_data) {
        set_sveil_error_message(_T("Memory allocation failed for combined data."));
        goto cleanup;
    }

    // Copy original image data
    memcpy(combined_data, image_data, image_data_size);

    // Append magic number
    size_t offset = image_data_size;
    memcpy(combined_data + offset, &magic_number, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    // Append encrypted data length
    memcpy(combined_data + offset, &encrypted_data_length, sizeof(uint32_t));
    offset += sizeof(uint32_t);

    // Append encrypted data
    memcpy(combined_data + offset, encrypted_data, encrypted_size);
    offset += encrypted_size;

    combined_data_size = offset;

    free(encrypted_data);

    // Compress the combined data
    uLongf compressed_size = compressBound((uLongf)combined_data_size);
    new_idat_data = (unsigned char*)malloc(compressed_size);
    if (!new_idat_data) {
        set_sveil_error_message(_T("Memory allocation failed for new IDAT data."));
        goto cleanup;
    }

    int ret = compress2(new_idat_data, &compressed_size, combined_data, (uLongf)combined_data_size, Z_BEST_COMPRESSION);
    if (ret != Z_OK) {
        set_sveil_error_message(_T("Failed to compress combined data."));
        goto cleanup;
    }
    new_idat_size = compressed_size;

    // Replace IDAT chunks with the new data
    if (replace_idat_chunks(&png_data, &png_size, idat_pos, idat_total_length, new_idat_data, new_idat_size) != 0) {
        set_sveil_error_message(_T("Failed to replace IDAT chunks."));
        goto cleanup;
    }

    // Write the modified PNG data to the output file
    fp = _tfopen(output_path, _T("wb"));
    if (!fp) {
        set_sveil_error_message(_T("Failed to open output file."));
        goto cleanup;
    }
    if (fwrite(png_data, 1, png_size, fp) != png_size) {
        set_sveil_error_message(_T("Failed to write output PNG file."));
        fclose(fp);
        goto cleanup;
    }
    fclose(fp);
    fp = NULL;

    // Success
    result = 0;

cleanup:
    if (fp) fclose(fp);
    if (data_fp) fclose(data_fp);
    if (png_data) free(png_data);
    if (idat_data) free(idat_data);
    if (data_buffer) free(data_buffer);
    if (image_data) free(image_data);
    if (combined_data) free(combined_data);
    if (new_idat_data) free(new_idat_data);

    return result;
}

// Removed Windows-only encrypt/derive implementations; using encryption.h now
