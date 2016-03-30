/******************************************************
*filename:timer_wheel.c
*function : Provide a timer_wheel mechanism to Aging the flow Entries.
*******************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include "timer_wheel.h"
#include "timeval.h"

struct timerwheel g_tw;
static int timer_add(struct timer *p)
{
    (void)p;
#if 0
    struct timer *timer;
    bool insert_flag = 0;
    //add two timers according to type
    unsigned int index = (g_tw.cur_index + p->interval/g_tw.time_accuracy)%g_tw.num;
    g_tw.cur_time = time_now_sec();
    p->timeout= g_tw.cur_time +  p->interval/g_tw.time_accuracy;

    LIST_FOR_EACH(timer, struct timer, node, g_tw.timer_list[index])
    {
        if(timer->timeout >= p->timeout)
        {
             list_insert(&timer->node, &p->node);
             insert_flag = 1;
             break;
        }
    }
    if( 0 == insert_flag )
    {
        list_push_back(g_tw.timer_list[index], &p->node);
    }
#endif
    return 0;
}

void * timerwheel_add(struct timer *p,const alta_aclTimer interval, timer_expiry *func, void *user_data)
{
    //struct timer_node *p = (struct timer_node *)malloc(sizeof(struct timer_node));
    if (!p)
    {
        return NULL;
    }
    memset(p, 0, sizeof(struct timer));
    p->func= func;
    p->interval = interval;
    p->user_data = user_data;
    timer_add(p);
    return p;
}

int timerwheel_del(struct timer *p)
{
    if(!p)
    {
        return 1;
    }
    list_remove(&p->node);
    return 0;
}

void  run_timers(void)
{
#if 0
    unsigned long diff;
    struct timer *timer=NULL;
    g_tw.cur_time = time_now_sec();
    if (0 == g_tw.pre_time)
    {
        g_tw.pre_time = g_tw.cur_time;
    }
    diff = (g_tw.cur_time -g_tw.pre_time)/g_tw.time_accuracy;
    if (diff > 0)
    {
        g_tw.pre_time = g_tw.cur_time;
        g_tw.cur_index += 1;
        if (g_tw.cur_index >= g_tw.num)
        {
            g_tw.cur_index = 0;
        }
    }
    else
    {
        return;
    }

    while(!list_is_empty(g_tw.timer_list[g_tw.cur_index]))
    {
        timer = list_pop_front(g_tw.timer_list[g_tw.cur_index]);
        //list_remove(&timer->node);
        if (timer && g_tw.cur_time >= timer->timeout)
        {
            if(0 == timer->func( timer->user_data))
            {
                timer->timeout= g_tw.cur_time +  timer->interval/g_tw.time_accuracy;
                list_push_back(g_tw.timer_list[g_tw.cur_index],&timer->node);
                break;
            }
        }
        else
        {
             list_push_back(g_tw.timer_list[g_tw.cur_index],&timer->node);
             break;
        }
     }
   #endif
    return;
}

int timerwheel_init(const unsigned int num, const unsigned int  time_accuracy)
{
#if 0
    int i = 0;
    memset(&g_tw, 0, sizeof(struct timerwheel));
    g_tw.timer_list = (struct list **)malloc(num*sizeof(struct list *));
    if (NULL == g_tw.timer_list)
    {
        return 1;
    }
    for (i = 0;i < num; i++)
    {
        g_tw.timer_list[i] = (struct list *) malloc (sizeof(struct list)) ;
        if(!g_tw.timer_list[i])
        {
            return 1;
        }
        list_init(g_tw.timer_list[i]); //初始化每一个链表头
    }
    g_tw.time_accuracy = time_accuracy;
    g_tw.num = num;
#endif
    (void)num;
    (void)time_accuracy;
    return 0;
}
