
#pragma once

#define	TAG_READ		0x85648485
#define	TAG_WRITE		0x89756453
#define TAG_GETMODULE	0x56165511
#define TAG_PROTECT		0x98844446
#define TAG_PROBEREAD	0x68468846

#pragma pack(push,1)
typedef struct _BOOM_PROCESS_OPERA {
	ULONG		tag;		//标记
	ULONG		flags;		//标记
	ULONG64		pid;		//target process
	ULONG64		address;	//读取地址
	ULONG64		buf;		//缓冲区指针
	ULONG		size;		//需要读取大小
}BOOM_PROCESS_OPERA, *PBOOM_PROCESS_OPERA;
#pragma pack(pop)