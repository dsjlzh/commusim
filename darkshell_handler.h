#ifndef __DARK_SHELL_HANDLER_H_
#define __DARK_SHELL_HANDLER_H_

/// application
#include "darkshell.h"

class dshellhandler : public bdatahandler
{
public :
    dshellhandler() {};
    dshellhandler(int fd) : bdatahandler(fd) 
    {
        socklen_t len = (socklen_t)sizeof(m_addr);
        getpeername(fd, (struct sockaddr *)&m_addr, &len);
    };
    
    ~dshellhandler() 
    {
        cout << "dshellhandler::~dshellhandler(): fd=" << m_fd;
        cout << ", " << inet_ntoa(m_addr.sin_addr) << ":"<< ntohs(m_addr.sin_port);
        m_factory->erase(this);
    };

    int on_read();
    int send_command();
    int on_command(string &, string &);
    int on_command(std::vector<std::string> &);
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

    int log_msg(bool, char data[], int len) {};
    
private:
    struct sockaddr_in m_addr;
    bhandlerfactory *m_factory;
    dshell_command m_cmd;
}; 

class dshellfactory : public bhandlerfactory
{
public:
    dshellfactory(){};
    ~dshellfactory(){};

public:
    bdatahandler *make(int);
    bdatahandler *find(bid &id);
    void showall();
    void erase(bdatahandler *handler)
    {
        std::list<dshellhandler *>::iterator iter;
        dshellhandler *p;
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
    std::list<dshellhandler *> m_handlers_list;
};

#endif

