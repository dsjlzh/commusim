//#include <pcap.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <time.h>
#include <malloc.h>
#include <pthread.h>
#include <fcntl.h>
#include <syslog.h>
#include <arpa/inet.h>

#include <iostream>
#include <sstream>
#include <fstream>
#include <cstdlib>
#include <ctime>
#include <assert.h>
#include <list>

#include "common.h"
#include "cb1st_handler.h"
#include "darkshell_handler.h"
#include "dslserverklr_handler.h"

#ifndef __GNUC__
//#include "stdafx.h"
#endif

void help()
{
    cout << "RSA Sample utility" << "\n";
}

int main(int argc, char **argv)
{
    // file to save decoded messages
    char log_file[256] = "/tmp/cb1st.msg";
    char data[10];
    bbuffer buf;

    // test bbuffer
    buf.enqueue(log_file, strlen(log_file));
    
    memset(data, 0, sizeof(data));
    buf.dequeue(data, 4);
    printf("%s\n", data);

    printf("%s, len=%d\n", buf.data(), buf.len());

    buf.dequeue(data, strlen(log_file) - 4);
    printf("%s\n", data);
    
#if 0
    if (argc < 2)
    {
        help();
        exit(-1);
    }
#endif

    //bhandlerfactory *factory = new cb1stfactory();
    bhandlerfactory *factory = new dshellfactory();
    int i;
    u_short listen_port = 0;
    for (i = 1; i < argc; )
    {
        if (!strcmp("-p", argv[i]))
        {
            i++;
            listen_port = atoi(argv[i]);
            i ++;
        }
        else if (!strcmp("-port", argv[i]))
        {
            i++;
            listen_port = atoi(argv[i]);
            i ++;
        }
        else if (!strcmp("-t", argv[i]))
        {
            test_deflate();
            i++;
        }
        else if (!strcmp("-o", argv[i]))
        {
            i++;
            strcpy(log_file,  argv[i]);
            i++;
        }
        else if (!strcmp("-bot", argv[i]) || !strcmp("-b", argv[i]))
        {
            i++;
            if (!strcmp("cb1st", argv[i]))
            {
                factory = new cb1stfactory();
            }
            else if (!strcmp("darkshell", argv[i])
                ||!strcmp("dshell", argv[i]))
            {
                factory = new dshellfactory();
            }
            else if (!strcmp("dsl", argv[i]))
            {
                factory = new dslfactory();
            }
            
            i++;
        }
#if 0
        else if (!strcmp("-o", argv[i]))
        {
            i++;
            memset(output_file, 0, sizeof(output_file));
            strncpy(output_file, argv[i], 254); 
            i++;
        }
        else if (!strcmp("-dns", argv[i]))
        {
            i++;
            extract_dns = 1;
            strcpy(filter_str, "udp port 53");
            i++;
        }
        else if (!strcmp("-hex", argv[i]))
        {
            i++;
            in_hex = 1;
            printf("hex=%d\n", in_hex);
        }
        else //if (!strcmp("-h", argv[i]))
        {
            if (*argv[i] != '-')
            {
                strcpy(pcap_file, argv[i]);
                i++;
            }
            else 
            {
                printf("invalid options \"%s\"\n", argv[i]);
                help();
                exit(0);
            }
        }
#endif
    }

    bdispatcher dispatcher;
    //bhandlerfactory *factory = dynamic_cast<bhandlerfactory*>(_factory);
    //cb1stfactory factory;

    int stdin = 0;
    fcntl(stdin, O_NONBLOCK, 1);
    bcommandhandler commander(stdin, factory);

    /* add the STDIN to the master set */
    dispatcher.add_handler(&commander);

    blistener listener(INADDR_ANY, listen_port, &dispatcher, factory);
    dispatcher.add_handler(&listener);

    dispatcher.poll();

    return 0;
}

