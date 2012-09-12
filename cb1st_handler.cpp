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
#include "cb1st.h"
#include "cb1st_handler.h"

using namespace std;

int cb1sthandler::on_read()
{
    int ret = bdatahandler::on_read();
    if (BERROR == ret)
    {
        return BERROR;
    }

    cb1st_hdr hdr;
    bdatahandler::copy((char *)&hdr, sizeof(hdr));

    printf("cb1sthandler::on_read(): peer=%s:%d, total=%d, olen=%d\n", 
        inet_ntoa(m_addr.sin_addr), ntohs(m_addr.sin_port), hdr.total_len, hdr.olen);
    if (m_buffer.len() < (hdr.total_len - sizeof(hdr)))
    {
        return BSUCCESS;
    }

     int j;
#if 1
    printf("msg_size1=%d\n", hdr.total_len - sizeof(hdr));    
    for (j = 0; j < hdr.total_len - sizeof(hdr); j++)
    {
        printf("%.2x ", *(m_buffer.data() + j));
    }
    printf("\n");
#endif

     // decompress 
    char message[2048];
    int msg_size = sizeof(message);
    cb1st_inflate((u_char *)m_buffer.data(), hdr.total_len - sizeof(hdr), 
        (u_char *)message, &msg_size);
    log_msg(true, message, msg_size);

    // dequeue handled data
    //bsockhandler::get((char *)message, hdr.total_len - sizeof(hdr));
    m_buffer.dequeue(hdr.total_len - sizeof(hdr));
    
#if 0
    printf("msg_size2=%d\n", msg_size2);
    //int j;
    for (j = 0; j < msg_size2; j++)
    {
        printf("%.2x ", *(message2+j));
    }
    printf("\n");
#endif

    // handle
    char  send_msg1[1024] = "";
    int send_size1 = sizeof(send_msg1);  // buf size
    cb1st_handle_msg((cb1st_msg *)message, msg_size, 
        (cb1st_msg *)send_msg1, &send_size1);
    //printf("after handle, olen=%d\n", send_msg->olen);
    
    //makeup,  compress and send

#if 0
    cb1st_hdr *send_msg2 = (cb1st_hdr *)message;
    memcpy(send_msg2->prefix, "cb1st", 5);
    send_msg2->total_len = sizeof(message) - sizeof(*send_msg2);
    cb1st_deflate(send_msg1, send_size1, send_msg2->data, &send_msg2->total_len);
    send_msg2->total_len += sizeof(cb1st_hdr);
    send_msg2->olen = send_size1;
    
#if 0
    printf("send_msg_size=%d\n", send_msg->total_len);                
    for (j = 0; j < send_msg->total_len; j++)
    {
        printf("%.2x ", *(send_buf + j));
    }
    printf("\n");
#endif

    return send((char *)send_msg2, send_msg2->total_len);
#endif

    if (send_size1 > 0)
    {
        return send((char *)send_msg1, send_size1);
    }

    return BSUCCESS;
}

int cb1sthandler::send(char data [ ],int len)
{
    u_char buf[2048];
    cb1st_hdr *send_msg2 = (cb1st_hdr *)buf;
    memcpy(send_msg2->prefix, "cb1st", 5);
    send_msg2->total_len = sizeof(buf) - sizeof(*send_msg2);
    cb1st_deflate((u_char *)data, len, send_msg2->data, &send_msg2->total_len);
    send_msg2->total_len += sizeof(cb1st_hdr);
    send_msg2->olen = len;

    printf("cb1sthandler::send(): code=%d, olen=%d\n", 
        *data, len);
    log_msg(false, data, len);
    
#if 0
    printf("send_msg_size=%d\n", send_msg->total_len);                
    for (j = 0; j < send_msg->total_len; j++)
    {
        printf("%.2x ", *(send_buf + j));
    }
    printf("\n");
#endif

    return bdatahandler::send((char *)send_msg2, send_msg2->total_len);
}

int cb1sthandler::log_msg(bool in, char data[], int len)
{
    int ret;
    if (in)
    {
        ret = save_message("./messages", CB1ST_MSG_PREFIX_INPUT, CB1ST_MSG_PREFIX_INPUT_LEN);
    }
    else
    {
        ret = save_message("./messages", CB1ST_MSG_PREFIX_OUTPUT, CB1ST_MSG_PREFIX_OUTPUT_LEN);
    }

    char buf[64];
    sprintf(buf, "%s:%d", inet_ntoa(m_addr.sin_addr), ntohs(m_addr.sin_port));
    ret += save_message("./messages", buf, strlen(buf));

    int padding = 0;
    char paded[] = "CCCCCCCCCCCCCCCCCCCCCCC";
    if ((strlen(buf) % 16) != 0)
    {
        int i;        
        padding = 16 - (strlen(buf) % 16);
        ret += save_message("./messages", paded, padding);
    }
    
    // in net order for easy reading
    len = htonl(len);
    ret += save_message("./messages", (char *)&len, sizeof(len));
    len = ntohl(len);
    
    ret += save_message("./messages", data, len);
    
    if (((len + 4) % 16) != 0)
    {
        int i;        
        padding = 16 - ((len + 4) % 16);
        ret += save_message("./messages", paded, padding);
    }

    return ret;
}


bdatahandler *cb1stfactory::make(int fd)
{
    printf("cb1stfactory::make: fd=%d\n", fd);
    cb1sthandler *handler = new cb1sthandler(fd);
    if (NULL == handler)
    {
        return NULL;
    }

    m_handlers_list.push_back(handler);
    handler->set_factory(this);
    return handler;
}

bdatahandler *cb1stfactory::find(bid &id)
{
    std::list<cb1sthandler *>::iterator iter;
    cb1sthandler *p;
    for (iter = m_handlers_list.begin(); iter != m_handlers_list.end(); iter++)
    {
        p = *iter;
        if (0 == p->compare(id))
        {
            return p;
        }
    }

    return NULL;
}

void cb1stfactory::showall()
{
    std::list<cb1sthandler *>::iterator iter;
    cb1sthandler *p;
    for (iter = m_handlers_list.begin(); iter != m_handlers_list.end(); iter++)
    {
        p = *iter;
        p->showid();
        cout << std::endl;
    }
}

int cb1stcommander::on_read()
{
    int ret = bcommandhandler::on_read();
    if (BERROR == ret)
    {
        cout << "cb1stcommander::on_read(): BERROR" << endl;
        return BERROR;
    }

    // No data
    if (0 == ret)
    {
        return BSUCCESS;
    }

    if (m_strs[0] == "id")
    {
        if (m_strs.size() < 3)
        {
            goto safe_out;
        }
        
        m_str_index++;

        int id = atoi(m_strs[1].c_str());
        bid bid(id);
        printf("to id %d\n", id);
        bdatahandler *handler = m_factory->find(bid);
        if (NULL == handler)
        {
            cout << "no handler for id " << id;
            goto safe_out;
        }

        char buf[512];
        cb1st_msg *msg = (cb1st_msg *)buf;
        int to_send = 1;
        msg->msg_code = (char)atoi(m_strs[2].c_str());
        if (53 == msg->msg_code)
        {            
            cb1st_msg_0x34_0x35 *msg_body = (cb1st_msg_0x34_0x35 *)msg->data;
            msg_body->index = 10;
            msg_body->dip = 0x8498a8c0;
            msg_body->dport = htons(atoi(m_strs[3].c_str()));
            msg_body->reserved = 100;
            to_send += sizeof(* msg_body);
        }
        
        handler->send(buf, to_send);
    }
    
    ret = BSUCCESS;

safe_out:
    
    return ret;
}

