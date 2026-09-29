/*
 * libFuzzer entry point.
 *
 * libFuzzer calls this once per generated input. It places the input in a
 * heap buffer sized exactly to `size`, so any read past `data + size` is a
 * real heap-buffer-overflow that AddressSanitizer catches precisely.
 *
 * We always call kv_free so LeakSanitizer stays quiet on the many inputs
 * that parse partially and then hit an error.
 */
#include "kvparse.h"

#include <stddef.h>
#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    kv_message msg;
    int rc = kv_parse(data, size, &msg);
    if (rc == KV_OK) {
        kv_free(&msg);
    }
    return 0;   /* non-zero return values are reserved by libFuzzer */
}
