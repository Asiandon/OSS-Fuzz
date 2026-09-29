/*
 * record.c — a second, deliberately vulnerable parser.
 *
 * This one demonstrates a different bug class from kvparse.c: a heap-buffer-
 * overflow WRITE (CWE-787), the "write" counterpart to kvparse's OOB read.
 *
 * Wire format:
 *   magic     "REC1"   4 bytes
 *   name_len           1 byte
 *   name               name_len bytes
 *
 * The parser allocates a FIXED 16-byte destination on the assumption that
 * names never exceed 16 bytes, then copies name_len bytes into it without
 * ever enforcing that assumption.
 */
#include "record.h"

#include <stdlib.h>
#include <string.h>

#define NAME_CAP 16   /* assumed max name length — never actually enforced */

int rec_parse(const uint8_t *data, size_t size, char **name_out, size_t *len_out) {
    if (name_out) *name_out = NULL;
    if (len_out)  *len_out  = 0;

    if (size < 5) return REC_ERR_SHORT;
    if (memcmp(data, "REC1", 4) != 0) return REC_ERR_MAGIC;

    uint8_t name_len = data[4];

    /* Bounds-check the READ against the input: this part is safe. */
    if ((size_t)5 + name_len > size) return REC_ERR_SHORT;

    /*
     * FIX: size the destination to the data that will be written into it,
     * instead of a hardcoded NAME_CAP that name_len may exceed. malloc(0) is
     * implementation-defined, so request at least 1 byte.
     */
    char *name = malloc(name_len ? name_len : 1);
    if (!name) return REC_ERR_NOMEM;

    memcpy(name, data + 5, name_len);   /* destination now always large enough */

    if (name_out) *name_out = name; else free(name);
    if (len_out)  *len_out  = name_len;
    return REC_OK;
}
