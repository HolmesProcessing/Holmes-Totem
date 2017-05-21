#include <stdio.h>
#include <stdlib.h>
#include "include/pe.h"

int main(void) {
    // Open binary file for parsing
    pe_ctx_t ctx;
    pe_err_e err = pe_load_file(&ctx, "umss.exe");
    if (err != LIBPE_E_OK) {
        pe_error_print(stderr, err);
        return EXIT_FAILURE;
    }

    // Parse binary file
    err = pe_parse(&ctx);
    if (err != LIBPE_E_OK) {
        pe_error_print(stderr, err);
        return EXIT_FAILURE;
    }

    if (!pe_is_pe(&ctx)) {
        return EXIT_FAILURE;
    }

    // Get COFF header information and output it
    IMAGE_OPTIONAL_HEADER_64 *optional = pe_optional(&ctx);
    printf("Machine: %x\n", optional->Magic);

    return 0;
}
