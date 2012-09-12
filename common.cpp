/*****************************************************************
* Big number algorithms including +, -, *, /, %, <<, >>. As much as 1024-bit big number is supported.
* Version: v 0.1, 2011/12/27
* 
*****************************************************************/
#ifdef _WIN32
//#include "stdafx.h"
#endif

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <list>
#include <vector>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cmath>
#include <ctime>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <time.h>
#include <malloc.h>
#include <pthread.h>
#include <fcntl.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <errno.h>
#endif

#include "common.h"

int save_message(char file[], char msg[], int len)
{
    FILE *filep = fopen(file, "a+b");
    if (filep == NULL)
    {
        printf("failed to filp_open \"%s\".\n", 
            file);
        return -1;
    }

    fwrite(msg, 1, len, filep);
    fclose(filep);
    
    return len;
}

int hex_dump(u_char * data, int len)
{
    int i;
    for (i = 0; i < len; )
    {
        //if (*(data + i) < 0x7F && *(data + i) >= 0x20)
        if (0)
        {
            printf("%c", *(data + i));
        }
        else 
        {
            printf("\\x%.2X", *(data + i));
        }

        i++;
        
        if ((i % 16) == 0)
        {
            printf("\n  ");
        }
    }
    printf("\n");

	return BSUCCESS;
}

int bbuffer::enqueue(char *data, int size)
{
    //printf("bbuffer::enqueue: write_pos=%d, size=%d\n",
    //    m_write_pos, size);
    if (size + m_write_pos > m_size)
    {
        char *new_buf = new char[size + m_write_pos];
        if (NULL == new_buf)
        {
            return BERROR;
        }

        m_size = size + m_write_pos;
        memcpy(new_buf, m_buf, m_write_pos);
        free(m_buf);
        m_buf = new_buf;
    }

    memcpy(m_buf + m_write_pos, data, size);
    m_write_pos += size ;

#if 0
    int j;
    for (j = 0; j < m_write_pos; j++)
    {
        printf("%.2x ", *(m_buf+j));
    }
    printf("\n");
#endif

    return m_write_pos;
}

int bbuffer::dequeue(char *buffer, int size)
{
    if (size > m_write_pos)
    {
        return BERROR;
    }

    //printf("bbuffer::dequeue(): total=%d, read_size=%d\n", 
    //    m_write_pos, size);

    memcpy(buffer, m_buf, size); 
    m_write_pos -= size;
    memmove(m_buf, m_buf + size, m_write_pos);
    return m_write_pos;
}

int bbuffer::dequeue(int size)
{
    if (size > m_write_pos)
    {
        return BERROR;
    }

    //printf("bbuffer::dequeue(): total=%d, read_size=%d\n", 
    //    m_write_pos, size);

    m_write_pos -= size;
    memmove(m_buf, m_buf + size, m_write_pos);
    return m_write_pos;
}

#ifndef _WIN32
int bdispatcher::poll()
{  
    fd_set read_fds;
    int fdmax = 0;
    int loops = 0;

LOOP:

    loops++;
    if (loops > 10)
    {
        //return BSUCCESS;
    }
    
    //printf("bdispatcher::poll(): loop ...\n");
    
    FD_ZERO(&read_fds);
    fdmax = 0;
    
    std::list<bhandler *>::iterator iter;
    bhandler *p;
    for (iter = m_handlers.begin(); iter != m_handlers.end(); iter++)
    {
        p = *iter;
        FD_SET(p->fd(), &read_fds);
        //printf("bdispatcher::poll(): fd_set fd %d\n", p->fd());
        if (p->fd() > fdmax)
        {
            fdmax = p->fd();
        }
    }

    //printf("bdispatcher::poll(): loop , fdmax=%d\n", fdmax);
    int ret = ::select(fdmax + 1, &read_fds, NULL, NULL, NULL) ;
    if (ret < 0)
    {
        printf("select() error, err=%d\n", errno);
        return BERROR;
    }

    //printf("bdispatcher::poll(): select ok %d\n", ret);
    
    for (iter = m_handlers.begin(); iter != m_handlers.end(); iter++)
    {
        p = *iter;
        //printf("bdispatcher::poll(): fd %d\n", p->fd());
        if (!FD_ISSET(p->fd(), &read_fds))
        {
            continue;
        }

        //printf("bdispatcher::poll(): fd %d is ready\n", p->fd());
        int ret = p->on_read();
        if (BERROR == ret)
        {
            
            m_handlers.erase(iter);
            delete p;
        }
        break;
    }

    goto LOOP;

    return BERROR;
} 

void bdispatcher::add_handler(bhandler *h)
{
    //printf("bdispatcher::set_handler(): set fd %d\n", h->fd());
    m_handlers.push_back(h);
}

blistener::blistener(int ip, u_short port, bdispatcher * dispatcher,  bhandlerfactory *factory)
    : m_dispatcher(dispatcher), m_factory(factory)
{
    int ret;
    
    m_fd = socket(AF_INET, SOCK_STREAM, 0);
    
    /* get the listener */
    if ( m_fd < 0)
    {
        perror("socket() error lol!");

        return;
    }

    printf("blistener::blistener(): socket() OK, fd=%d\n", m_fd);

    /*"address already in use" error message */
     int yes = 1;
    ret = setsockopt(m_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
    if (ret < 0)
    {
        printf("setsockopt() error lol, fd=%d, errno=%d!", m_fd, errno);
        return;
    }

    printf("blistener::blistener(): setsockopt() OK\n");     

    /* bind */
    struct sockaddr_in serveraddr;
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = htons(ip);  //INADDR_ANY;
    serveraddr.sin_port = htons(port);
    memset(&(serveraddr.sin_zero), '\0', 8);     
    ret = bind(m_fd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) ;
    if (ret < 0)
    {
        perror("Server-bind() error lol!");
        return;
    }
    printf("blistener::blistener(): bind() OK\n");
    
    /* listen */
    if (listen(m_fd, 10) == -1)
    {
         perror("Server-listen() error lol!");
         return;
    }
    printf("listen() OK\n");
}

int blistener::on_read()
{
    struct sockaddr_in clientaddr;
    socklen_t addrlen = sizeof(clientaddr);
    int client_fd = accept(m_fd, (struct sockaddr *)&clientaddr, &addrlen);
    if (client_fd <= 0)
    {
        printf("blistener::blistener(): accept() error, errno=%d\n", errno);
        return BERROR;
    }
    
    printf("blisterner::on_read(): new client, fd=%d, ip=%s, port=%d\n", 
        client_fd, inet_ntoa(clientaddr.sin_addr), ntohs(clientaddr.sin_port));

    fcntl(client_fd, O_NONBLOCK, 1);
    m_dispatcher->add_handler(dynamic_cast<bhandler *>(m_factory->make(client_fd)));
    
    return BSUCCESS;
}

//using namespace boost;
int bdatahandler::on_command(string &key, string &value)
{
    cout << "bdatahandler::on_command(),  " << key << ":"<< value << endl;
    
    return BSUCCESS;
}

int bdatahandler::on_read()
{
    char buf[2048];
    int bytes = read(m_fd, buf, sizeof(buf));  //recv(m_fd, buf, sizeof(buf), 0);
    if (bytes <= 0)
    {
        printf("bdatahandler::on_read(): socket %d hung up\n", m_fd);
        close(m_fd);
        m_fd = -1;
        return BERROR;
    }
    
    //printf("bdatahandler::on_read(): %d bytes read on fd %d.\n", 
    //    bytes, m_fd);

    m_buffer.enqueue(buf, bytes);
    return m_buffer.len();
}

int bdatahandler::send(char data[], int len)
{
    int ret = ::write(m_fd, data, len);
    return (ret > 0) ? ret : BERROR;
}

int bdatahandler::copy(char buf[], u_int size)
{
    return m_buffer.dequeue(buf, size);
}

int bcommandhandler::on_read()
{
    int ret = BERROR;
    int read = bdatahandler::on_read();
    if (BERROR == read)
    {
        return BERROR;
    }
    
    //cout << "bcommandhandler::on_read(): " << read << endl;
    if (read <= 2)
    {
        m_buffer.dequeue(read);
        return 0;
    }

    // on command
    char buffer[256];
    memset(buffer, 0, sizeof(buffer));
    bdatahandler::copy(buffer, read);
    
    std::string cmd = buffer;
    trim(cmd);
    //cout << "bcommandhandler::on_read(): " << cmd << endl;
    
    m_strs.clear();
    m_str_index = 0;

    //cout << "bcommandhandler::on_read(): ::split()" << endl;
    ::Split(m_strs, cmd, " ");  // 
    if (m_strs.size() <= 0)
    {
        goto safe_out;
    }

    if (m_strs[0] == "list")
    {
        m_factory->showall();
        ret = BSUCCESS;
    }
    else if (m_strs[0] == "id")
    {
        if (m_strs.size() < 3)
        {
            goto safe_out;
        }
        
        int id = atoi(m_strs[1].c_str());
        bid bid(id);
        printf("to id %d\n", id);
        bdatahandler *handler = m_factory->find(bid);
        
        if (NULL == handler)
        {
            cout << "no handler for id " << id;
            goto safe_out;
        }

        m_strs.erase(m_strs.begin());
        m_strs.erase(m_strs.begin());

        str_vector_t::iterator iter;
        for (iter = m_strs.begin(); iter != m_strs.end(); )
        {
            std::string & opt = *iter;
            iter++;
            std::string value;
            if (iter == m_strs.end()
                || (*iter).c_str()[0] == '-'
                )
            {
                value = "";
            }
            else 
            {
                value = *iter;
                iter++;
            }

            ::lower(opt);
            handler->on_command(opt, value);
        }
        
        //ret = handler->on_command(m_strs);
        ret = handler->send_command();
    }

safe_out:
    //cout << "bcommandhandler::on_read(): size="<< m_strs.size() << endl;
    return ret;
}

#endif

int Split(str_vector_t &strs, std::string &str, std::string pattern = " ")
{
    std::string::size_type pos;
    //std::vector<std::string> *strs = new std::vector<std::string>();
    str += pattern;  //扩展字符串以方便操作
    int size = str.size();

    for(int i=0; i<size; i++)
    {
        pos=str.find(pattern, i);
        if (pos < size)
        {
            std::string s = str.substr(i, pos-i);
            if (s.size() > 0)
            {
                strs.push_back(s);
            }
            i = pos + pattern.size() - 1;
        }
    }
    return strs.size();
}

std::string& trim(std::string &s)
{
    if (s.empty())
    {
        return s;
    }

    // space
    s.erase(0,s.find_first_not_of(" "));
    s.erase(s.find_last_not_of(" ") + 1);

    // tab
    s.erase(0,s.find_first_not_of("\t"));
    s.erase(s.find_last_not_of("\t") + 1);

    // 0x0D
    s.erase(s.find_last_not_of("\n") + 1);
    return s;
}

string lower(string &str)
{
    transform(str.begin(), str.end(), str.begin(), ::tolower);
    return str;
}

