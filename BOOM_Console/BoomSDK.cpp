
#include <windows.h>
#include "BoomDef.h"
#include "BoomSDK.h"



void
BO_ZwLoadDriver();

__int64
BO_GetProcessImageBase(ULONG64 pid)
{
	__int64 imageBase = 0;
	BOOM_PROCESS_OPERA	input = { 0 };

	input.tag = TAG_GETMODULE;
	input.pid = pid;
	input.address = NULL;
	input.buf = (UCHAR*)&imageBase;
	input.size = sizeof(imageBase);

	RegSetValueExA(HKEY_LOCAL_MACHINE,
				  "",
				  NULL,
				  REG_BINARY,
				  (byte*)&input,
				  48);

	return imageBase;
}

void
BO_ProtectProcess(ULONG64 pid)
{
	BOOM_PROCESS_OPERA	input = { 0 };

	input.tag = TAG_PROTECT;
	input.pid = pid;
	input.address = NULL;
	input.buf = NULL;
	input.size = NULL;

	RegSetValueExA(HKEY_LOCAL_MACHINE,
		"",
		NULL,
		REG_BINARY,
		(byte*)&input,
		48);
}

int
BO_ReadInt32(ULONG64 pid, ULONG64 address);

__int64
BO_ReadInt64(ULONG64 pid, ULONG64 address);

void
BO_ReadBytes(ULONG64 pid, ULONG64 address, PBYTE byteBuf, ULONG size);

float
BO_ReadFloat(ULONG64 pid, ULONG64 address);

double
BO_ReadDouble(ULONG64 pid, ULONG64 address);

void
BO_WriteInt32(ULONG64 pid, ULONG64 address, int data);

void
BO_WriteInt64(ULONG64 pid, ULONG64 address, __int64 data);

void
BO_WriteBytes(ULONG64 pid, ULONG64 address, PBYTE data, ULONG size);

void
BO_WriteFloat(ULONG64 pid, ULONG64 address, float data);

void
BO_WriteDouble(ULONG64 pid, ULONG64 address, double data);



