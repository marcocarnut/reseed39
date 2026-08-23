/*
 * rxe_wasm.c -- thin C shim exposing librxe's enumeration primitives to
 * WebAssembly / JavaScript for the bip39rxcrack effort ESTIMATOR.
 *
 * THE DRIFT RULE: this file adds NO set-counting or bijection logic of its
 * own. Cardinality comes straight from librxe's rxe->nitems; unrank is
 * rxe_seek + rxe_current. The estimator model (checksum survival, path
 * multiplier, ETA) lives in JavaScript on top of these exact counts, so the
 * future native CLI links the SAME librxe and can never disagree.
 *
 * All 64-bit-unsafe values (cardinalities, indices) cross the JS boundary as
 * decimal STRINGS (BigInt on the JS side), never as doubles.
 *
 * Ownership: every char* returned here is malloc'd and must be released by the
 * caller via rxew_free_str(). Every handle from rxew_parse() via rxew_free().
 */

#include <emscripten.h>
#include <gmp.h>
#include <stdlib.h>
#include <string.h>
#include "rxe.h"

/* Longest member we will render for a dry-run sample. Passphrases/mnemonics
 * are short; this is a generous ceiling that also bounds runaway repeats. */
#define RXEW_RENDER_CAP (1u << 16)   /* 64 KiB */

/* ----- parse / lifecycle ------------------------------------------------- */

EMSCRIPTEN_KEEPALIVE
void *rxew_parse(const char *pattern, int flags)
{
    return rxe_parse(pattern, flags);
}

EMSCRIPTEN_KEEPALIVE
int rxew_error(void *r)
{
    return rxe_error((struct rxe *)r);
}

EMSCRIPTEN_KEEPALIVE
const char *rxew_error_message(void *r)
{
    /* points into a static table in librxe; do NOT free on the JS side */
    return rxe_error_message((struct rxe *)r);
}

EMSCRIPTEN_KEEPALIVE
int rxew_error_pos(void *r)
{
    return rxe_error_pos((struct rxe *)r);
}

EMSCRIPTEN_KEEPALIVE
int rxew_is_infinite(void *r)
{
    return rxe_is_infinite((struct rxe *)r);
}

EMSCRIPTEN_KEEPALIVE
int rxew_is_shortlex(void *r)
{
    return rxe_is_shortlex((struct rxe *)r);
}

EMSCRIPTEN_KEEPALIVE
void rxew_free(void *r)
{
    if (r) rxe_free((struct rxe *)r);
}

EMSCRIPTEN_KEEPALIVE
void rxew_free_str(char *s)
{
    if (s) free(s);
}

/* ----- cardinality ------------------------------------------------------- */

/* Total number of members, as a decimal string. Meaningful only for a finite
 * set: for an infinite one rxe->nitems counts the finite alternations alone,
 * so the JS layer must gate on rxew_is_infinite() first. mpz_get_str(NULL,...)
 * allocates with the active GMP allocator (libc malloc by default), so the JS
 * side releases it with rxew_free_str(). */
EMSCRIPTEN_KEEPALIVE
char *rxew_cardinality(void *r)
{
    struct rxe *rxe = (struct rxe *)r;
    return mpz_get_str(NULL, 10, rxe->nitems);
}

/* ----- unrank ------------------------------------------------------------ */

/* The i-th member (i as a decimal string), or NULL if the index is out of
 * range / negative / unparseable / the member overflows the render cap. This
 * is librxe's bijection: rxe_seek(i) then rxe_current(). Returned string is
 * malloc'd; free with rxew_free_str(). */
EMSCRIPTEN_KEEPALIVE
char *rxew_unrank(void *r, const char *index_dec)
{
    struct rxe *rxe = (struct rxe *)r;
    mpz_t idx;
    mpz_init(idx);
    if (mpz_set_str(idx, index_dec, 10) != 0) { mpz_clear(idx); return NULL; }
    if (mpz_sgn(idx) < 0) { mpz_clear(idx); return NULL; }
    if (!rxe_is_infinite(rxe) && mpz_cmp(idx, rxe->nitems) >= 0) {
        mpz_clear(idx);
        return NULL;
    }
    rxe_check_overflow();
    if (rxe_seek(rxe, idx)) { mpz_clear(idx); return NULL; }
    mpz_clear(idx);

    char *buf = (char *)malloc(RXEW_RENDER_CAP + 1);
    if (!buf) return NULL;
    rxe_current(buf, RXEW_RENDER_CAP, rxe);
    if (rxe_check_overflow()) { free(buf); return NULL; }
    return buf;
}

/* ----- rank (inverse: string -> smallest index, as decimal) -------------- */

/* Smallest index at which string s sits, or NULL if s is not a member or the
 * set is one rank cannot handle. Used to sanity-check unrank round-trips. */
EMSCRIPTEN_KEEPALIVE
char *rxew_rank(void *r, const char *s)
{
    struct rxe *rxe = (struct rxe *)r;
    mpz_t out;
    mpz_init(out);
    if (rxe_rank(rxe, s, out) != 0) { mpz_clear(out); return NULL; }
    char *res = mpz_get_str(NULL, 10, out);
    mpz_clear(out);
    return res;
}

/* ----- dictionaries ([:name:]) ------------------------------------------- */

/* Register a word dictionary named `name` from a newline-separated blob (as a
 * .dict file's contents). librxe deep-copies the words, so the temporaries we
 * build here are freed before returning. A trailing empty line is ignored.
 * Returns the number of words registered, or -1 on allocation failure. */
EMSCRIPTEN_KEEPALIVE
int rxew_register_dict(const char *name, const char *blob)
{
    /* count lines (words) */
    int n = 0;
    const char *p = blob;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        if (len > 0) n++;
        if (!nl) break;
        p = nl + 1;
    }
    if (n == 0) { const char *empty[1]; (void)empty; return rxe_register_dict(name, NULL, 0); }

    const char **words = (const char **)malloc((size_t)n * sizeof(char *));
    if (!words) return -1;
    char **owned = (char **)malloc((size_t)n * sizeof(char *));
    if (!owned) { free(words); return -1; }

    int i = 0;
    p = blob;
    while (*p && i < n) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        if (len > 0) {
            char *w = (char *)malloc(len + 1);
            if (!w) { for (int k = 0; k < i; k++) free(owned[k]); free(owned); free(words); return -1; }
            memcpy(w, p, len);
            w[len] = 0;
            owned[i] = w;
            words[i] = w;
            i++;
        }
        if (!nl) break;
        p = nl + 1;
    }
    int rc = rxe_register_dict(name, words, i);
    for (int k = 0; k < i; k++) free(owned[k]);
    free(owned);
    free(words);
    return rc == 0 ? i : -1;
}
