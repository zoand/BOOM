#pragma once

#include <tchar.h>
#include <windows.h>

#include "../inc/inc.h"

class CDrvController
{
public:
	CDrvController();
	~CDrvController();

	//
	//是否已加载驱动
	//
	BOOL DC_IsLoadBoomDrv();

	//
	//获取模块基址
	//
	ULONG64 DC_GetModuleAddr(ULONG pid, LPCWSTR lpModuleName);

	//
	//提交物理页,用于刚使用VirtualAlloc申请内存后，需要立刻写入
	//
	BOOL DC_ProbeRead(ULONG pid, ULONG64 addr);

	//-------------------------------READ--------------------------------------------------

	//
	//读内存 字节型(BYTE)
	//
	BYTE DC_ReadByte(ULONG pid, ULONG64 addr);

	//
	//读内存 短整数型(SHORT)
	//
	SHORT DC_ReadShort(ULONG pid, ULONG64 addr);

	//
	//读内存 整数型(INT)
	//
	INT DC_ReadInt(ULONG pid, ULONG64 addr);

	//
	//读内存 长整数型(INT64)
	//
	INT64 DC_ReadInt64(ULONG pid, ULONG64 addr);

	//
	//读内存 浮点型(FLOAT)
	//
	FLOAT DC_ReadFloat(ULONG pid, ULONG64 addr);

	//
	//读内存 字节集(Bytes)
	//
	BOOL DC_ReadBytes(ULONG pid, ULONG64 addr, _Out_ PBYTE pDataBuffer, ULONG size);

	//-------------------------------WRITE--------------------------------------------------

	//
	//写内存 字节型(BYTE)
	//
	BOOL DC_WriteByte(ULONG pid, ULONG64 addr, _In_ BYTE pDataBuffer);

	//
	//写内存 短整数型(SHORT)
	//
	BOOL DC_WriteShort(ULONG pid, ULONG64 addr, _In_ SHORT pDataBuffer);

	//
	//写内存 整数型(INT)
	//
	BOOL DC_WriteInt(ULONG pid, ULONG64 addr, _In_ INT pDataBuffer);

	//
	//写内存 长整数型(INT64)
	//
	BOOL DC_WriteInt64(ULONG pid, ULONG64 addr, _In_ INT64 pDataBuffer);

	//
	//写内存 浮点型(FLOAT)
	//
	BOOL DC_WriteFloat(ULONG pid, ULONG64 addr, _In_ FLOAT pDataBuffer);

	//
	//写内存 字节集(Bytes)
	//
	BOOL DC_WriteBytes(ULONG pid, ULONG64 addr, _In_ PBYTE pDataBuffer, ULONG size);

private:

	BOOL ReadMemory(ULONG64 pid, ULONG64 addr, _Out_ PBYTE pDataBuffer, ULONG size);

	BOOL WriteMemory(ULONG64 pid, ULONG64 addr, _In_ PBYTE pDataBuffer, ULONG size);

 };

