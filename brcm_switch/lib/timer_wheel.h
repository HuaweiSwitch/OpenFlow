 /*****************************************************
*filename: timer_wheel.h
******************************************************/
#ifndef __TIMER_WHEEL__
#define __TIMER_WHEEL__
#include "list.h"
typedef int timer_expiry( void *user_data);

typedef struct _alta_aclTimer
{
    unsigned char type;
    /** timer for hardware timerout. */
    int  hardtimer;

    /** timer for idle timerout. */
    int  idletimer;

} alta_aclTimer;

struct timer{
    struct list node;
    alta_aclTimer interval; /*定时器超时值*/
    time_t timeout;	 /*超时时间 */
    timer_expiry *func;	 /*定时器回调函数*/
    void *user_data;	 /*定时器传入参数*/
};

/*定时器管理*/
struct timerwheel{
    unsigned int   time_accuracy;	 /*定时器时间片大小*/
    unsigned int   num;	 /*定时器最大数量*/
    unsigned int   cur_index;	 /*定时器当前时间片大小*/
    time_t  cur_time;	 /*定时器当前时间*/
    time_t  pre_time;	 /*定时器上一个时间*/
    struct list **timer_list;
};

int  timerwheel_init(const unsigned int num, const unsigned int  time_accuracy);
int  timerwheel_del(struct timer *p);
void *  timerwheel_add(struct timer *p,const alta_aclTimer interval, timer_expiry *func, void *user_data);
void  run_timers(void);

#endif

