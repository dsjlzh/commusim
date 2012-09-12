/*****************************************************************
 * Created on 2012/01/31
****************************************************************/

#include <iostream>
#include <iomanip>
#include <ctime>

#include <pcap.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <time.h>
#include <malloc.h>
#include <pthread.h>
#include <fcntl.h>
#include <syslog.h>
#include <arpa/inet.h>

#include <zlib.h>

#include "common.h"
#include "darkshell.h"

using namespace std;

//
// for cb1st botnet decompress/compress

#if 0
// not thread-safe
int dshell_handle_pcap(
    struct timeval *ts,
    unsigned int sip,
    u_short sport,
    unsigned int dip,
    u_short dport,
    u_char data[],
    int len  // not including tcp header
    )
{
    struct tm *tm;
    //unsigned short sport = ntohs(tcphdr->th_sport);
    //unsigned short dport = ntohs(tcphdr->th_dport);
        
#define CB1ST_CMD_BUF_SIZE 2048
    static u_char cmd_data[CB1ST_CMD_BUF_SIZE];
    static int write_pos = 0;
    
    u_char uncompr[CB1ST_CMD_BUF_SIZE];
    int uncomprLen = CB1ST_CMD_BUF_SIZE;
    
    cb1st_hdr *hdr = (cb1st_hdr *)cmd_data;
    int ret = -1;
    int i;
    
    //printf("sizeof()=%d, offset=%d\n", 
    //    sizeof(cb1st_hdr), (char *)&(hdr->total_len) - (char *)hdr);

    if (write_pos >= CB1ST_CMD_BUF_SIZE)
    {
        printf("buf overflow1, %u.%u.%u.%u:%d -> %u.%u.%u.%u:%d, "
            "write_pos=%d, cb1st.total_len=%d!\n",
            sip&0xFF, (sip>>8)&0xFF,(sip>>16)&0xFF,(sip>>24)&0xFF, sport,
            dip&0xFF, (dip>>8)&0xFF,(dip>>16)&0xFF,(dip>>24)&0xFF, dport,
            write_pos, (hdr->total_len)
            );
        write_pos = 0;  // clear
        return -1;
    }
    
    memcpy(cmd_data + write_pos, data, min(len, CB1ST_CMD_BUF_SIZE - write_pos));
    write_pos += min(len, CB1ST_CMD_BUF_SIZE - write_pos);
    if (write_pos != (hdr->total_len))
    {
        if (write_pos > (hdr->total_len))
        {
            printf("buf overflow2, %u.%u.%u.%u:%d -> %u.%u.%u.%u:%d, "
                "write_pos(=%d) > cb1st.total_len(=%d)!\n",
                sip&0xFF, (sip>>8)&0xFF,(sip>>16)&0xFF,(sip>>24)&0xFF, sport,
                dip&0xFF, (dip>>8)&0xFF,(dip>>16)&0xFF,(dip>>24)&0xFF, dport,
                write_pos, (hdr->total_len)
                );
            write_pos = 0;  // clear
            return -1;
        }

        printf("data not enough, %u.%u.%u.%u:%d -> %u.%u.%u.%u:%d, "
            "write_pos(=%d) > cb1st.total_len(=%d)!\n",
            sip&0xFF, (sip>>8)&0xFF,(sip>>16)&0xFF,(sip>>24)&0xFF, sport,
            dip&0xFF, (dip>>8)&0xFF,(dip>>16)&0xFF,(dip>>24)&0xFF, dport,
            write_pos, (hdr->total_len)
            );

        return 0;
    }

    ret = cb1st_inflate(hdr->data, (hdr->total_len) - sizeof(*hdr), uncompr, &uncomprLen);
    if (ret < 0)
    {
        printf("failed to inflate, %u.%u.%u.%u:%d -> %u.%u.%u.%u:%d, "
            "cb1st.total_len=%d\n",
            sip&0xFF, (sip>>8)&0xFF,(sip>>16)&0xFF,(sip>>24)&0xFF, sport,
            dip&0xFF, (dip>>8)&0xFF,(dip>>16)&0xFF,(dip>>24)&0xFF, dport,
            (hdr->total_len)
            );
        return -1;
    }

    // display uncompressed data
    tm = localtime(&ts->tv_sec);
    printf("%.4i-%.2i-%.2i %.2i:%.2i:%.2i, "
        "%u.%u.%u.%u:%d -> %u.%u.%u.%u:%d, ", 
        1900 + tm->tm_year,1+ tm->tm_mon,tm->tm_mday,tm->tm_hour,tm->tm_min,tm->tm_sec,
        sip&0xFF, (sip>>8)&0xFF,(sip>>16)&0xFF,(sip>>24)&0xFF, sport,
        dip&0xFF, (dip>>8)&0xFF,(dip>>16)&0xFF,(dip>>24)&0xFF, dport);
    printf("total_len=%d, old_len=%d\n  ", hdr->total_len, hdr->olen);
    for (i = 0; i < uncomprLen; )
    {
        // by "-hex ", default in ascii mode
        if (in_hex)
        {
            printf("%.2X ", *(uncompr + i));
        }
        else
        {            
            if (*(uncompr + i) < 0x7F && *(uncompr + i) >= 0x20)
            {
                printf("%c", *(uncompr + i));
            }
            else 
            {
                printf(".");
            }
        }

        i++;
        
        if ((i % 16) == 0)
        {
            printf("\n  ");
        }
    }
    printf("\n\n");
    
    write_pos = 0;  // clear
    return 0;
}

void pcap_handler_dshell(
    char *usr, 
    const struct pcap_pkthdr *pcapheader, 
    const u_char *pkt
    ) 
{
    struct ip_h *ip_hdr;
    struct tcphdr *tcp_hdr;
    int len;
    int ret;

    static int number = 0;
    //printf("pcap_handler_cb1st(): pkt # %d\n", number++);    
    
    //----- ignore packets that are just too short
    if (pcapheader->caplen < sizeof(struct eth_h) + sizeof(*ip_hdr) + sizeof(*tcp_hdr))
    {	
    	printf("invalid packet!\n");
        return;
    }

    ip_hdr = (struct ip_h*)(pkt + sizeof(struct eth_h));
    if (ip_hdr->proto != 0x06)  // TCP
    {
        printf("not tcp!\n");
        return;
    }
    
    tcp_hdr = (struct tcphdr *)((char *)ip_hdr + ((ip_hdr->vhl &0x0F) << 2));
    if (!(tcp_hdr->th_flags & TH_PSH))
    {
        // no payload, skip!
        //printf("no payload\n");
        return;
    }

    len = ntohs(ip_hdr->len) - ((ip_hdr->vhl &0x0F) << 2) - (tcp_hdr->th_off 
<< 2);
     if (pcapheader->caplen - len != sizeof(struct eth_h) + ((ip_hdr->vhl &
0x0F) << 2) + 
        (tcp_hdr->th_off << 2))
    {	
    	printf("invalid packet len, tcphdr_len=%d, len=%d, pkt_len=%d!\n",
            (tcp_hdr->th_off << 2), len, pcapheader->caplen);
        return;
    }

    if (0 == len)
    {
        printf("PUSH set, but no payload!\n");
        return;
    }
    
    ret = cb1st_handle_pcap((struct timeval *)&pcapheader->ts, ip_hdr->src.s_addr, ntohs(tcp_hdr->th_sport),
        ip_hdr->dst.s_addr, ntohs(tcp_hdr->th_dport), 
        (u_char *)tcp_hdr + (tcp_hdr->th_off << 2), len);
    
    return;
}
#endif

#if 0
char *msg_descr[CB1ST_MSG_CODE_MAX] =
{
    [CB1ST_MSG_CODE_PING] = "Ping",
    [CB1ST_MSG_CODE_PONG] = "Pong",
    [CB1ST_MSG_CODE_REGISTER] = "Register",
    [CB1ST_MSG_CODE_REGISTER_RESP] = "Register response",
    [CB1ST_MSG_CODE_VER_TOO_LOW ] = "Server version too low",
};
#endif

#if 0
int dshell_handle_msg(
    cb1st_msg *msg_recv,
    int recv_len,  // in bytes
    cb1st_msg *msg_resp,
    int *resp_len  // in bytes
    )
{
    u_char *p = msg_resp->data;
    int left = *resp_len;
    int i;

    //printf("cb1st_handle_msg(): code=0x%.2X\n", msg_recv->msg_code);
    //save_message(char file [ ], msg_recv, recv_len)
    
    switch (msg_recv->msg_code)
    {
    case CB1ST_MSG_CODE_REGISTER:
    {        
        printf("cb1st_handle_msg(): on CB1ST_MSG_CODE_REGISTER\n");
        printf("version=");
#if 0
        //int i;
        //cb1st_register_msg *register_msg = (cb1st_register_msg *)msg_recv->data;
        for (i = 0; i < 20; i++) 
        {
            printf("%.2X", register_msg->VersionInfoEx[i]);
        }
        printf("\n");
#endif
        CB1ST_HANDLE_MSG_CHECK_BUF(left, register_resp_len);
        msg_resp->msg_code = CB1ST_MSG_CODE_REGISTER_RESP;
        memcpy(msg_resp->data, register_resp, register_resp_len - 1);
        *resp_len = register_resp_len;
        printf("*resp_len=%d\n", *resp_len);
        break;
    }
    case CB1ST_MSG_CODE_PING:
        printf("cb1st_handle_msg(): on CB1ST_MSG_CODE_PING\n");
        msg_resp->msg_code = CB1ST_MSG_CODE_PONG;
        *resp_len = 1;
        break;

    case CB1ST_MSG_CODE_VER_TOO_LOW:
        printf("cb1st_handle_msg(): on CB1ST_MSG_CODE_VER_TOO_LOW\n");
        *resp_len = 0;
        break;
        
    default:
        
        printf("cb1st_handle_msg(): unknown code %d\n", msg_recv->msg_code);
        *resp_len = 0;
#if 0
        printf("data: ");
        for (i = 0; i < recv_len; i++) 
        {
            printf("%.2X ", msg_recv->data[i]);
        }
        printf("\n");
#endif
        break;
    }

    printf("cb1st_handle_msg(): resp_code=0x%.2X, len=%d\n\n", 
        msg_resp->msg_code, *resp_len);

    return *resp_len;
}
#endif

#if 0
int cb1st_handle_cmd(
    u_char command,
    cb1st_msg *msg_resp,
    int *resp_len  // in bytes
    )
{
    //u_char *p = msg_resp->data;
    //int left = *resp_len;
    int i;

    msg_resp->msg_code = command;
    switch (command)
    {
    case CB1ST_MSG_CODE_DDOS:    
        printf("cb1st_handle_cmd(): on CB1ST_MSG_CODE_DDOS\n");        
        *resp_len = 1;
        break;

    default:
        *resp_len = 1;
        break;
    }

    return *resp_len;
}
#endif

void dshell_decrypt(u_char *data, int len, u_char key)
{
    while ( len > 0)
    {
        u_char key2 = (key % 254) + 1;
        *data = (*data - key2) ^ key2;
        ++data;
        --len;
    }
}

void dshell_encrypt(u_char *data, int len, u_char key)
{
    if ( len != 0)
    {
        do
        {
            u_char key2 = (key % 254) + 1;
          *data = ((*data)  ^ key2) + key2;
          ++data;
          --len;
        }
        while ( len > 0);
    }
}

