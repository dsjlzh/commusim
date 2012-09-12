#ifndef _COMMON_H_
#define _COMMON_H_

#include <iostream>
#include <sstream>
#include <fstream>
#include <cstdlib>
#include <ctime>
#include <string>
#include <list>
#include <vector>

#define BERROR -1
#define BSUCCESS 0

#define min(a, b) (((a) < (b))? (a):(b))

using namespace std;

#ifdef _WIN32

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;

#else

typedef unsigned int DWORD;
typedef unsigned short WORD;

#endif

struct eth_h
{
  uint8_t  dhost[6];   // destination mac
  uint8_t  shost[6];   // source mac
  uint16_t type;       // ethernet frame type
};

struct ip_h
{
  uint8_t  vhl;        // version & header length 
  uint8_t  tos;        // type of service 
  uint16_t len;        // datagram length 
  uint16_t id;         // identification
  uint16_t foff;       // fragment offset
  uint8_t  ttl;        // time to live field
  uint8_t  proto;      // datagram protocol
  uint16_t csum;       // checksum
  struct in_addr src;   // source IP
  struct in_addr dst;   // dest IP
};

struct udp_h {
  uint16_t     sport;  // source port
  uint16_t     dport;  // destination port
  uint16_t     len;    // length
  uint16_t     csum;   // checksum
};

struct tcphdr {
	u_short	th_sport;		/* source port */
	u_short	th_dport;		/* destination port */
	uint32_t	th_seq;			/* sequence number */
	uint32_t	th_ack;			/* acknowledgement number */
	u_char	th_x2:4,		/* (unused) */
		    th_off:4;		/* data offset */
	u_char	th_flags;
#define	TH_FIN	0x01
#define	TH_SYN	0x02
#define	TH_RST	0x04
#define	TH_PSH	0x08
#define	TH_ACK	0x10
#define	TH_URG	0x20
	u_short	th_win;			/* window */
	u_short	th_sum;			/* checksum */
	u_short	th_urp;			/* urgent pointer */
};

typedef std::vector<std::string> str_vector_t;

class bid
{
public :
    bid() : m_id(0) {};
    bid(int id) : m_id(id) {};
    ~bid() {};

public:
    virtual int id_compare(bid *) {return -1;};
    virtual int compare(bid &id)
    {
        return (m_id == id.m_id ) ? 0: 1;
    }
    virtual void showid() 
    {
        cout << "id: "<< m_id ;
    };
    
    virtual string id()  {return "";};

private:
    int m_id;
};

class bbuffer
{
public :
    bbuffer() : m_buf(NULL),  m_size (0), m_write_pos (0)  {};

    bbuffer(int size) 
    {
        m_buf = new char[size];
        m_write_pos = 0;
        m_size = size;
    };
    
    ~bbuffer() {};

public:
    int enqueue(char *data, int size);

    int dequeue(char *buffer, int size);
    int dequeue(int size);

    int len() const
    {
        return m_write_pos;
    };

    char *data()
    {
        return m_buf;
    };
    
private:
    char *m_buf;
    int m_size;
    int m_write_pos;
};

#ifndef _WIN32
class bhandler
{
public :
    bhandler() :m_fd (-1) {};

    bhandler(int fd) {m_fd = fd;};
    
    virtual ~bhandler() 
    {
         if (m_fd > 0) 
        {
            close(m_fd);
        }
    };
    
public:
    virtual int on_read() = 0;
    
    //virtual void on_accept() = 0;
    
    int fd() const
    {
        return m_fd;
    };

protected:
    int m_fd;
}; 

class bdispatcher
{
//public :
    //enum {reader, writer} type;
    
public :
    bdispatcher() {};
    ~bdispatcher() {};
    
public:
    int poll();
    void add_handler(bhandler *);

private:
    std::list<bhandler *> m_handlers;
}; 

class bdatahandler;

class bhandlerfactory
{
public:
    bhandlerfactory(){};
    ~bhandlerfactory(){};

public:
    virtual bdatahandler *make(int) = 0;
    virtual bdatahandler *find(bid &id) = 0;
    virtual void showall() = 0;
    virtual void erase(bdatahandler *) = 0;
};

class blistener : public bhandler
{
public :
    blistener(bdispatcher * dispatcher, bhandlerfactory *factory)
        : m_dispatcher(dispatcher), m_factory(factory) {};    
    blistener(int, u_short, bdispatcher * , bhandlerfactory *);
    ~blistener() {};
    
    int on_read();

    int fd() const;

private:
    blistener() {};
    
private:
    bdispatcher *m_dispatcher; 
    bhandlerfactory *m_factory;
}; 

class bdatahandler : public bhandler, public bid
{
public :
    bdatahandler() : bid(-1) {};

    bdatahandler(int fd) : bhandler(fd), bid(fd) {};
    
    ~bdatahandler() 
    {
        if (m_fd > 0) 
        {
            close(m_fd);
            m_fd = -1;
        }
    };

public:  // inherited from class bid

#if 0
    int compare(bid &id2)
    {
        //if (istypeof(id2))
        {
            id id = dynamic_cast<bsockhandler::id> id2;
            return (m_fd == id.m_fd)? 0 : 1;
        }
    };
#endif

    virtual void showid()
    {
        bid::showid();
    };

public:  // inherited from class bhandler
    virtual int on_read();

    virtual int on_command(std::vector<std::string> &) 
    {
        return BSUCCESS;
    };

    virtual int on_command(string &, string &);
 
    virtual int send_command() {return BSUCCESS;};

    virtual int send(char [], int);

    // copy data out
    int copy(char [], u_int );
    
protected:
    //int m_fd;
    bbuffer m_buffer;
}; 

class bcommandhandler: public bdatahandler
{
public :
    bcommandhandler() : bdatahandler(-1), m_factory(NULL) {};

    bcommandhandler(int fd, bhandlerfactory *factory) 
        : bdatahandler(fd), m_factory(factory) {};
    
    ~bcommandhandler() 
    {
        m_strs.clear();
    };

public:    
    virtual int on_read();    

    void set_factory(bhandlerfactory *factory)
    {
        m_factory = factory;
    };

protected:    
    std::vector<std::string> m_strs;
    int m_str_index;
    
//private:
    bhandlerfactory *m_factory;
};

int save_message(char file[], char msg[], int len);

int hex_dump(u_char *data, int len);
#endif

std::string& trim(std::string &s);

std::string lower(string &str);

int Split(std::vector<std::string> &strs, std::string &str, std::string pattern);

#endif
