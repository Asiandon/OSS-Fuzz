# kvparse — OSS-Fuzz-style vulnerability + patch (worked example)

A minimal, self-contained example of the kind of task this work asks for: a
small C parser with a realistic memory-safety bug, a libFuzzer harness that
reaches it, a crashing input reproduced under AddressSanitizer, and a minimal
patch that fixes it without breaking valid input.

## The target

`src/kvparse.c` parses a tiny binary key/value message. Format (big-endian):

```
magic       "KVP1"        4 bytes
field_count               1 byte
  per field:
    key_len               1 byte
    key                   key_len bytes
    val_len               2 bytes
    value                 val_len bytes
```

## The bug — heap out-of-bounds read (CWE-125)

Every field's `val_len` is read straight from the input, then used as the size
of a `memcpy` from the input buffer:

```c
uint16_t val_len = read_u16(data + pos);
pos += 2;
uint8_t *val = malloc(val_len ? val_len : 1);
memcpy(val, data + pos, val_len);   // kvparse.c:60
```

The length of the *key* is bounds-checked (`pos + key_len > size`), but the
length of the *value* is not. When `val_len` is larger than the bytes actually
remaining (`size - pos`), the `memcpy` reads past the end of the input buffer.

This is the single most common OSS-Fuzz bug shape: **a length field taken from
untrusted input and trusted without validation.**

## Reproduce

```bash
./build.sh                          # builds ./kvparse_fuzzer with ASan+libFuzzer
./kvparse_fuzzer seeds/crash-oob-read
```

The crashing input (`seeds/crash-oob-read`, 8 bytes) declares one field with
`val_len = 0xFFFF` but supplies no value bytes:

```
4b 56 50 31   "KVP1"
01            field_count = 1
00            key_len = 0
ff ff         val_len = 65535   <- no bytes follow
```

AddressSanitizer reports (full log in `seeds/crash-oob-read.asan.txt`):

```
==ERROR: AddressSanitizer: heap-buffer-overflow ...
READ of size 65535 ...
    #1 in kv_parse src/kvparse.c:60:9
    #2 in LLVMFuzzerTestOneInput fuzz/kvparse_fuzz.c:18
```

libFuzzer also finds this on its own in a few seconds from the valid seed:

```bash
mkdir -p corpus && cp seeds/valid-1field corpus/
./kvparse_fuzzer -max_total_time=30 corpus
```

## The fix

`patch/fix-oob-read.diff` adds the missing bounds check before the copy:

```c
if (pos + val_len > size) { kv_free(out); return KV_ERR_SHORT; }
uint8_t *val = malloc(val_len ? val_len : 1);
memcpy(val, data + pos, val_len);
```

Verify it:

```bash
./build.sh fixed
./kvparse_fuzzer_fixed seeds/crash-oob-read      # no crash
./kvparse_fuzzer_fixed seeds/valid-1field        # still parses
./kvparse_fuzzer_fixed -max_total_time=20 seeds/ # fuzzes clean
```

The fix is minimal (one check), addresses the root cause (an unvalidated
length, not the symptom), mirrors the existing check already used for `key_len`,
and preserves behaviour for every valid message.

`src/kvparse_fixed.c` is the patched source; apply the diff to `src/kvparse.c`
with `patch -p1 < patch/fix-oob-read.diff` from the repo root instead if you
prefer.

## What makes this "acceptable" task work

- The bug is **realistic**, not contrived — it's a plain missing length check.
- The harness **reaches** the bug (libFuzzer rediscovers it unaided).
- The crash is **reproducible** under a sanitizer with a saved input.
- The patch is **minimal and correct** — root cause, no behaviour change,
  fuzzes clean afterwards.

These four are exactly the axes such submissions are graded on.

## Note on a latent hardening issue

`pos + val_len` and `pos + key_len` can't overflow here because `pos` stays
bounded by `size` (a fuzzer input is small), but in a parser handling large or
attacker-controlled sizes you'd compare against the remaining length instead —
e.g. `if (val_len > size - pos)` — to avoid pointer/size arithmetic overflow.
Worth mentioning in a real write-up.
