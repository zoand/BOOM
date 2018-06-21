#ifndef _BOOM_DEFINE_STRUCT_H
#define _BOOM_DEFINE_STRUCT_H

#define	TAG_READ		0xAEFCBD88DEADC0DE
#define	TAG_WRITE		0xAEFCBD88E0CDC0DE
#define TAG_GETMODULE	0xAEFCBD88C0EDC0DE
#define TAG_PROTECT		0xAEFCBD88ECADC0DE
#define TAG_PROBEREAD	0xAEFCBD880DADC0DE


typedef struct _BOOM_PROCESS_OPERA{
	ULONG64		tag;		//标记
	ULONG		flags;		//标记
	ULONG64		pid;		//target process
	ULONG64		address;	//读取地址
	UCHAR		*buf;		//缓冲区指针
	ULONG		size;		//需要读取大小
}BOOM_PROCESS_OPERA,*PBOOM_PROCESS_OPERA;


#endif