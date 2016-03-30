/*
 * Copyright (c) 2010, 2011 Nicira Networks.
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

#ifndef UNALIGNED_H
#define UNALIGNED_H 1

#include <stdint.h>
#include "byte-order.h"

/* Public API. */
static inline unsigned short int get_unaligned_u16(const unsigned short int *);
static inline unsigned int get_unaligned_u32(const unsigned int *);
static inline unsigned long long int get_unaligned_u64(const unsigned long long int *);
static inline void put_unaligned_u16(unsigned short int *, unsigned short int);
static inline void put_unaligned_u32(unsigned int *, unsigned int);
static inline void put_unaligned_u64(unsigned long long int *, unsigned long long int);

/* Generic implementations. */

static inline unsigned short int get_unaligned_u16(const unsigned short int *p_)
{
    const unsigned char *p = (const unsigned char *) p_;
    return ntohs((p[0] << 8) | p[1]);
}

static inline void put_unaligned_u16(unsigned short int *p_, unsigned short int x_)
{
    unsigned char *p = (unsigned char *) p_;
    unsigned short int x = ntohs(x_);

    p[0] = x >> 8;
    p[1] = x;
}

static inline unsigned int get_unaligned_u32(const unsigned int *p_)
{
    const unsigned char *p = (const unsigned char *) p_;
    return ntohl((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]);
}

static inline void put_unaligned_u32(unsigned int *p_, unsigned int x_)
{
    unsigned char *p = (unsigned char *) p_;
    unsigned int x = ntohl(x_);

    p[0] = x >> 24;
    p[1] = x >> 16;
    p[2] = x >> 8;
    p[3] = x;
}

static inline unsigned long long int get_unaligned_u64(const unsigned long long int *p_)
{
    const unsigned char *p = (const unsigned char *) p_;
    return ntohll(((unsigned long long int) p[0] << 56)
                  | ((unsigned long long int) p[1] << 48)
                  | ((unsigned long long int) p[2] << 40)
                  | ((unsigned long long int) p[3] << 32)
                  | (p[4] << 24)
                  | (p[5] << 16)
                  | (p[6] << 8)
                  | p[7]);
}

static inline void put_unaligned_u64(unsigned long long int *p_, unsigned long long int x_)
{
    unsigned char *p = (unsigned char *) p_;
    unsigned long long int x = ntohll(x_);

    p[0] = x >> 56;
    p[1] = x >> 48;
    p[2] = x >> 40;
    p[3] = x >> 32;
    p[4] = x >> 24;
    p[5] = x >> 16;
    p[6] = x >> 8;
    p[7] = x;
}



#endif /* unaligned.h */
