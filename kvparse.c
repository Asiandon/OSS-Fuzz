#include "kvparse.h"

#include <stdlib.h>
#include <string.h>

/* Read a big-endian uint16 from p. Caller guarantees 2 bytes are available. */
static uint16_t read_u16(const uint8_t *p) {
    return (uint16_t)((p[0] << 8) | p[1]);
}

void kv_free(kv_message *m) {
    if (!m) return;
    for (uint8_t i = 0; i < m->field_count && i < KV_MAX_FIELDS; i++) {
        free(m->fields[i].value);
        m->fields[i].value = NULL;
    }
    m->field_count = 0;
}

int kv_parse(const uint8_t *data, size_t size, kv_message *out) {
    memset(out, 0, sizeof(*out));

    /* Header is 4-byte magic + 1-byte field_count = 5 bytes minimum. */
    if (size < 5) return KV_ERR_SHORT;
    if (memcmp(data, "KVP1", 4) != 0) return KV_ERR_MAGIC;

    size_t pos = 4;
    uint8_t field_count = data[pos];
    pos += 1;

    if (field_count > KV_MAX_FIELDS) return KV_ERR_TOOMANY;
    out->field_count = field_count;

    for (uint8_t i = 0; i < field_count; i++) {
        /* --- key_len (1 byte) --- */
        if (pos + 1 > size) { kv_free(out); return KV_ERR_SHORT; }
        uint8_t key_len = data[pos];
        pos += 1;

        /* --- key (key_len bytes) --- bounds-checked, so this read is safe. */
        if (pos + key_len > size) { kv_free(out); return KV_ERR_SHORT; }
        memcpy(out->fields[i].key, data + pos, key_len);
        out->fields[i].key_len = key_len;
        pos += key_len;

        /* --- val_len (2 bytes) --- */
        if (pos + 2 > size) { kv_free(out); return KV_ERR_SHORT; }
        uint16_t val_len = read_u16(data + pos);
        pos += 2;

        /* --- value (val_len bytes) ---
         *
         * BUG: val_len comes straight from the input and is never checked
         * against the number of bytes actually remaining (size - pos).
         * When val_len > size - pos, the memcpy below reads past the end of
         * the input buffer: a heap-buffer-overflow READ.
         */
        uint8_t *val = malloc(val_len ? val_len : 1);
        if (!val) { kv_free(out); return KV_ERR_NOMEM; }
        memcpy(val, data + pos, val_len);     /* <-- out-of-bounds read here */
        out->fields[i].value = val;
        out->fields[i].val_len = val_len;
        pos += val_len;
    }

    return KV_OK;
}
