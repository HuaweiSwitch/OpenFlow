#ifndef ALTA_RBUFF_H
#define ALTA_RBUFF_H 1

struct rbuff
{
    int head;
    int tail;
    int size;
    int cnt;
    void **buff;
};

struct rbuff * rbuff_alloc(int size);
void rbuff_release(struct rbuff *rbuff);
int rbuff_cnt(struct rbuff *rbuff);
void * rbuff_get(struct rbuff *rbuff);
int rbuff_put(struct rbuff *rbuff, void *buff);
int rbuff_full(struct rbuff* buffer);

#endif
