#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "status.h"
#define FIFO_FILE_M "/home/pipe_file_m"
#define FIFO_FILE_S "/home/pipe_file_s"
/*当前代码中创建了两个管道:查询ofprotocol状态的管道是master管道，查询之后通过slave管道将事件通知给ofprotocl进程*/
void main(void)
{
    int fd_m = 0;
    int fd_s = 0;
    int flag = 0;
    int bytes_read = 0;
    int Ret = 0;
    char ofprotocol[1] = {0};
    char ofprotocol_new[1] = {0};
    /*创建slave管道*/
    if((-1 == access(FIFO_FILE_S,F_OK)) || (-1 == access(FIFO_FILE_S,F_OK)))            //文件是否存在
    {
        printf("Ofprotocol program is not run yet!\n");
        return ;
    }

    /*打开并且读取master管道*/
    fd_m = open(FIFO_FILE_M,O_RDWR | O_NONBLOCK);
    if(-1 == fd_m)
    {
        printf("Failed to open master pipe file, err is %s\n",strerror(errno));
        return ;
    }
    //printf("the master file`s descriptor is %d\n",fd_m);

    (void)read(fd_m,(void*)ofprotocol,sizeof(ofprotocol));
    /*根据读取到的值打印出对应的状态*/
    if (PROTOCOL_CONNECTTED == ofprotocol[0])
    {
        printf("/**********************************************************************/\n");
        printf("/*********************The protocol is connected!***********************/\n");
        printf("/**********************************************************************/\n");
    }
    if (PROTOCOL_DISCONNECT == ofprotocol[0])
    {
        printf("/**********************************************************************/\n");
        printf("/*******************The protocol is not connected!*********************/\n");
        printf("/**********************************************************************/\n");
    }

    /*通过slave管道将状态反馈给ofprotocl进程*/
    fd_s = open(FIFO_FILE_S,O_RDWR | O_NONBLOCK);
    if(-1 == fd_s)
    {
        printf("Failed to open the slave file, err is %s\n",strerror(errno));
        return ;
    }

    ofprotocol_new[0] = PROTOCOL_MAX;
    (void)write(fd_s,(void*)ofprotocol_new,sizeof(ofprotocol_new));

    if(-1 == close(fd_m))
    {
         printf("Failed to close master fd %d:%s\n", fd_m, strerror(errno));
    }

    if(-1 == close(fd_s))
    {
         printf("Failed to close slave fd %d:%s\n", fd_s, strerror(errno));
    }
    return ;
}

