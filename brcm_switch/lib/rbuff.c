#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

#include "rbuff.h"

/* ring buffer, only one producter and one consumer allowed, otherwise data race will occurr */

#define RBUFF_EMPTY(buffer) (buffer->cnt <= 0)
#define RBUFF_FULL(buffer)  (buffer->cnt >= buffer->size)
#define RBUFF_DESTROY(pointer)    \
{   \
    if (pointer)    \
    {   \
        free(pointer);  \
        pointer = NULL; \
    }   \
}

struct rbuff * rbuff_alloc(int size)
{
    struct rbuff *buffer;

    buffer = malloc(sizeof(*buffer));
    assert(buffer);

    memset(buffer, 0 ,sizeof(*buffer));
    buffer->buff = malloc(size * sizeof(void *));
    assert(buffer->buff);

    buffer->size = size;
    memset(buffer->buff, 0, size * sizeof(void *));

    return buffer;
}

void rbuff_release(struct rbuff *buffer)
{
    RBUFF_DESTROY(buffer->buff);
    RBUFF_DESTROY(buffer);

    return;
}

/* just for load balance between rbuffs */
int rbuff_cnt(struct rbuff *buffer)
{
    return buffer->cnt;
}

/* not thread-safe in multi consumer environment */
void * rbuff_get(struct rbuff *buffer)
{
    void *buff;

    if (!buffer||RBUFF_EMPTY(buffer))
    {
        return NULL;
    }

    buff = buffer->buff[buffer->head];
    buffer->buff[buffer->head] = NULL;
    buffer->head++;
    buffer->head = buffer->head % buffer->size;
    __sync_fetch_and_sub(&buffer->cnt, 1);

    return buff;
}

/* not thread-safe in multi producter environment */
int rbuff_put(struct rbuff *buffer, void *buff)
{
    if (RBUFF_FULL(buffer))
    {
        return -1;
    }

     buffer->buff[buffer->tail] = buff;
     buffer->tail++;
     buffer->tail = buffer->tail % buffer->size;
     __sync_fetch_and_add(&buffer->cnt, 1);

    return 0;
}

/*if buffer is full.*/
int rbuff_full(struct rbuff* buffer)
{
    if (RBUFF_FULL(buffer))
    {
        return 1;
    }
    
    return 0;
}

