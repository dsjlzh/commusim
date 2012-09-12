#ifndef __CB1ST_H_
#define __CB1ST_H_

#define CHECK_ERR(err, msg) { \
    if (err != Z_OK) { \
        fprintf(stderr, "%s error: %d\n", msg, err); \
        return -1; \
    } \
}

#define min(a, b) (((a) < (b))? (a):(b))

#define CB1ST_MSG_CODE_DDOS 0x34

#define CB1ST_MSG_CODE_PING 0x65  // from client
#define CB1ST_MSG_CODE_PONG 0x31  // from server

#define CB1ST_MSG_CODE_REGISTER 0x66
#define CB1ST_MSG_CODE_REGISTER_RESP 0x00  

#define CB1ST_MSG_CODE_VER_TOO_LOW 0x90

#define CB1ST_MSG_CODE_MAX 0xFF

#pragma pack(push)
#pragma pack(1)
typedef struct _cb1st_hdr
{
    char prefix[5] ;  //__attribute__((packed));
    int total_len;  // after compressed, including the header
    int olen;  // length before compress
    u_char data[0];
} cb1st_hdr;

typedef struct _cb1st_msg
{
    u_char msg_code;  //__attribute__((packed));
    u_char data[0];  
} cb1st_msg;

typedef unsigned int DWORD;
typedef unsigned short WORD;

typedef struct _cb1st_register_msg
{
    //u_char				MsgCode; 
    u_char OsVersionInfo[156];  //OSVERSIONINFOEX	OsVersionInfo;		//操作系统版本信息
    DWORD				CPUHz;					//CPU频率
    DWORD				IpAddress;			//IP地址
    char				HostName[50];			//主机名
    u_char				UNKNOWN2;
    u_char				UNKNOWN3;				//0xAA 含义未知
    DWORD				UNKNOWN4;				//是两个GetTickCount的差
    WORD				NumberOfProcessor;	//处理器数量
    DWORD				TotalPhyMemMB;		//全部物理内存，单位MB
    DWORD				FreePhyMemMB;			//剩余物理内存，单位MB
    DWORD				TotalDiskMB;			//全部磁盘空间，单位MB
    DWORD				FreeDiskMB;			//剩余磁盘空间，单位MB
    char				szMagic[6]; 			//'100622' 含义未知

    DWORD				DateTimeStamp;		//本PE文件里的DATETIME
    char				VersionInfo[258];	//"2011" 含义未知
    DWORD				UNKNOWN5;
    DWORD				UNKNOWN6;
    DWORD				UNKNOWN7;
    DWORD				UNKNOWN8;
    char				DiskNumber[20];		//硬盘序列号
    u_char				UNKNOWN9;				//0x46 含义未知
    char				VersionInfoEx[20];	//“中级版”BOT版本类型
    DWORD ProcessCreationTime[2];  //LARGE_INTEGER		ProcessCreationTime;//进程创建时间
    char				UNKNOWN10;
    DWORD				UNKNOWN11;
    DWORD				UNKNOWN12;
}cb1st_register_msg;

typedef struct _cb1st_msg_0x34_0x35
{
    int index;
    int dip;
    u_short dport;
    u_short reserved;
} cb1st_msg_0x34_0x35;

#pragma pack(pop)

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

 int cb1st_deflate(u_char * data, int len, u_char *compr, int *comprLen);
int cb1st_inflate(u_char * compr, int comprLen,  u_char *uncompr, int *uncomprLen);

#endif

