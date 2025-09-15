#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <tchar.h>
#include "../compat/compat.h"

#include "data_embed.h"

static void print_usage(const char* prog) {
    printf("Usage:\n");
    printf("  %s embed <png> <file> <out.png> <password>\n", prog);
    printf("  %s extract <png> <out_dir> <password>\n", prog);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "embed") == 0) {
        if (argc != 6) { print_usage(argv[0]); return 1; }
        const TCHAR* png = (const TCHAR*)argv[2];
        const TCHAR* file = (const TCHAR*)argv[3];
        const TCHAR* out = (const TCHAR*)argv[4];
        const TCHAR* pass = (const TCHAR*)argv[5];
        if (embed_data_in_png(png, file, out, pass) != 0) {
            printf("Error: %s\n", get_last_error_message());
            return 2;
        }
        printf("Embed OK -> %s\n", out);
        return 0;
    } else if (strcmp(argv[1], "extract") == 0) {
        if (argc != 5) { print_usage(argv[0]); return 1; }
        const TCHAR* png = (const TCHAR*)argv[2];
        const TCHAR* out_dir = (const TCHAR*)argv[3];
        const TCHAR* pass = (const TCHAR*)argv[4];
        TCHAR out_file[1024];
        if (extract_data_from_png(png, out_dir, pass, out_file) != 0) {
            printf("Error: %s\n", get_last_error_message());
            return 2;
        }
        printf("Extract OK -> %s\n", out_file);
        return 0;
    }

    print_usage(argv[0]);
    return 1;
}

