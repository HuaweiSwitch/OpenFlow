/*
 * Copyright (c) 2008, 2009, 2010 Nicira Networks.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "hash.h"
#include <string.h>

/* Returns the hash of the 'n' 32-bit words at 'p', starting from 'basis'.
 * 'p' must be properly aligned. */
unsigned int
hash_words(const unsigned int *p, size_t n, unsigned int basis)
{
    unsigned int a, b, c;

    a = b = c = 0xdeadbeef + (((unsigned int) n) << 2) + basis;

    while (n > 3) {
        a += p[0];
        b += p[1];
        c += p[2];
        HASH_MIX(a, b, c);
        n -= 3;
        p += 3;
    }

    switch (n) {
    case 3:
        c += p[2];
        /* fall through */
    case 2:
        b += p[1];
        /* fall through */
    case 1:
        a += p[0];
        HASH_FINAL(a, b, c);
        /* fall through */
    case 0:
        break;
    }
    return c;
}

/* Returns the hash of 'a', 'b', and 'c'. */
unsigned int
hash_3words(unsigned int a, unsigned int b, unsigned int c)
{
    a += 0xdeadbeef;
    b += 0xdeadbeef;
    c += 0xdeadbeef;
    HASH_FINAL(a, b, c);
    return c;
}

/* Returns the hash of 'a' and 'b'. */
unsigned int
hash_2words(unsigned int a, unsigned int b)
{
    return hash_3words(a, b, 0);
}

/* Returns the hash of the 'n' bytes at 'p', starting from 'basis'. */
unsigned int
hash_bytes(const void *p_, size_t n, unsigned int basis)
{
    const unsigned char *p = p_;
    unsigned int a, b, c;
    unsigned int tmp[3];

    a = b = c = 0xdeadbeef + n + basis;

    while (n >= sizeof tmp) {
        memcpy(tmp, p, sizeof tmp);
        a += tmp[0];
        b += tmp[1];
        c += tmp[2];
        HASH_MIX(a, b, c);
        n -= sizeof tmp;
        p += sizeof tmp;
    }

    if (n) {
        tmp[0] = tmp[1] = tmp[2] = 0;
        memcpy(tmp, p, n);
        a += tmp[0];
        b += tmp[1];
        c += tmp[2];
        HASH_FINAL(a, b, c);
    }

    return c;
}
