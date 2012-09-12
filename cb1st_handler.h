#ifndef __CB1ST_HANDLER_H_
#define __CB1ST_HANDLER_H_

#include "cb1st.h"

/// application

class cb1sthandler : public bdatahandler
{
public :
    cb1sthandler() {};
    cb1sthandler(int fd) : bdatahandler(fd) 
    {
        socklen_t len = (socklen_t)sizeof(m_addr);
        getpeername(fd, (struct sockaddr *)&m_addr, &len);
    };
    
    ~cb1sthandler() 
    {
        cout << "cb1sthandler::~cb1sthandler(): fd=" << m_fd;
        cout << ", " << inet_ntoa(m_addr.sin_addr) << ":"<< ntohs(m_addr.sin_port);
        m_factory->erase(this);
    };

    int on_read();
    int send(char data [],int len);
    
    void showid()
    {
        bid::showid();
        cout << ", " << inet_ntoa(m_addr.sin_addr) << ":"<< ntohs(m_addr.sin_port);
    };

    void set_factory(bhandlerfactory *factory)
    {
        m_factory = factory;
    };

    int log_msg(bool, char data[], int len);
    
private:
    struct sockaddr_in m_addr;
    bhandlerfactory *m_factory;
}; 

class cb1stfactory : public bhandlerfactory
{
public:
    cb1stfactory(){};
    ~cb1stfactory(){};

public:
    bdatahandler *make(int);
    bdatahandler *find(bid &id);
    void showall();
    void erase(bdatahandler *handler)
    {
        std::list<cb1sthandler *>::iterator iter;
        cb1sthandler *p;
        for (iter = m_handlers_list.begin(); iter != m_handlers_list.end(); iter++)
        {
            if (handler == *iter)
            {
                m_handlers_list.erase(iter);
                break;
            }
        }
    };

private:
    std::list<cb1sthandler *> m_handlers_list;
};

class cb1stcommander : public bcommandhandler
{
public:
    cb1stcommander() {};

    cb1stcommander(int fd, bhandlerfactory *factory) 
        : bcommandhandler(fd, factory) {};
    ~cb1stcommander() {};
    
public:
    int on_read();
};

void pcap_handler_cb1st(
    char *usr, 
    const struct pcap_pkthdr *pcapheader, 
    const u_char *pkt
    ) ;

int cb1st_handle_msg(
    cb1st_msg *msg_recv,
    int recv_len,  // in bytes
    cb1st_msg *msg_resp,
    int *resp_len  // in bytes
    );

int cb1st_handle_cmd(
    u_char command,
    cb1st_msg *msg_resp,
    int *resp_len  // in bytes
    );

#define CB1ST_MSG_PREFIX_INPUT "<<<<<<<<<<<<<<<<<<<<<<<<"
#define CB1ST_MSG_PREFIX_INPUT_LEN 16

#define CB1ST_MSG_PREFIX_OUTPUT ">>>>>>>>>>>>>>>>>>>>>>"
#define CB1ST_MSG_PREFIX_OUTPUT_LEN 16

int save_message(char file[], char msg[], int len);

void test_deflate(void );

#endif

