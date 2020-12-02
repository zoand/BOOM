
#include "CDrvController.h"

 
CDrvController::CDrvController()
{
}


CDrvController::~CDrvController()
{
}

BOOL CDrvController::DC_IsLoadBoomDrv()
{
	DWORD data1 = 666;
	DWORD data2 = 0;

	if (ReadMemory((ULONG64)GetCurrentProcessId(),(ULONG64)&data1,(PBYTE)&data2,sizeof(DWORD)))
	{
		if (data1 == data2)
		{
			return TRUE;
		}
	}

	return FALSE;
}

ULONG64 CDrvController::DC_GetModuleAddr(ULONG pid, LPCWSTR lpModuleName)
{
	BOOM_PROCESS_OPERA control = { 0 };

	WCHAR buf[MAX_PATH] = { 0 };

	control.tag = TAG_GETMODULE;
	control.pid = (ULONG64)pid;
	control.buf = (ULONG64)buf;

	if (lpModuleName != NULL)
	{
		wcscpy(buf, lpModuleName);
	}

	RegSetValueEx(HKEY_LOCAL_MACHINE, _T(""), NULL, REG_BINARY, (byte*)&control, sizeof(control));

	return *(ULONG64*)&buf;
}

BOOL CDrvController::DC_ProbeRead(ULONG pid, ULONG64 addr)
{
	BOOM_PROCESS_OPERA control = { 0 };

	control.tag = TAG_PROBEREAD;
	control.pid = (ULONG64)pid;
	control.address = (ULONG64)addr;

	RegSetValueEx(HKEY_LOCAL_MACHINE, _T(""), NULL, REG_BINARY, (byte*)&control, sizeof(control));

	return TRUE;
}

BYTE CDrvController::DC_ReadByte(ULONG pid, ULONG64 addr)
{
	BYTE buf = '\0';
	ReadMemory(pid, addr, (PBYTE)&buf, sizeof(BYTE));
	return buf;
}

SHORT CDrvController::DC_ReadShort(ULONG pid, ULONG64 addr)
{
	SHORT buf = 0;
	ReadMemory(pid, addr, (PBYTE)&buf, sizeof(SHORT));
	return buf;
}

INT CDrvController::DC_ReadInt(ULONG pid, ULONG64 addr)
{
	INT buf = 0;
	ReadMemory(pid, addr, (PBYTE)&buf, sizeof(INT));
	return buf;
}

INT64 CDrvController::DC_ReadInt64(ULONG pid, ULONG64 addr)
{
	INT64 buf = 0;
	ReadMemory(pid, addr, (PBYTE)&buf, sizeof(INT64));
	return buf;
}

FLOAT CDrvController::DC_ReadFloat(ULONG pid, ULONG64 addr)
{
	FLOAT buf = 0.0f;
	ReadMemory(pid, addr, (PBYTE)&buf, sizeof(FLOAT));
	return buf;
}

BOOL CDrvController::DC_ReadBytes(ULONG pid, ULONG64 addr, PBYTE pDataBuffer, ULONG size)
{
	return ReadMemory(pid, addr, pDataBuffer, size);
}

BOOL CDrvController::DC_WriteByte(ULONG pid, ULONG64 addr, BYTE pDataBuffer)
{
 	return WriteMemory(pid, addr, (PBYTE)&pDataBuffer, sizeof(BYTE));
}

BOOL CDrvController::DC_WriteShort(ULONG pid, ULONG64 addr, SHORT pDataBuffer)
{
	return WriteMemory(pid, addr, (PBYTE)&pDataBuffer, sizeof(SHORT));
}

BOOL CDrvController::DC_WriteInt(ULONG pid, ULONG64 addr, INT pDataBuffer)
{
	return WriteMemory(pid, addr, (PBYTE)&pDataBuffer, sizeof(INT));
}

BOOL CDrvController::DC_WriteInt64(ULONG pid, ULONG64 addr, INT64 pDataBuffer)
{
	return WriteMemory(pid, addr, (PBYTE)&pDataBuffer, sizeof(INT64));
}

BOOL CDrvController::DC_WriteFloat(ULONG pid, ULONG64 addr, FLOAT pDataBuffer)
{
	return WriteMemory(pid, addr, (PBYTE)&pDataBuffer, sizeof(FLOAT));
}

BOOL CDrvController::DC_WriteBytes(ULONG pid, ULONG64 addr, PBYTE pDataBuffer, ULONG size)
{
	return WriteMemory(pid, addr, pDataBuffer, size);
}

BOOL CDrvController::ReadMemory(ULONG64 pid, ULONG64 addr, PBYTE pDataBuffer, ULONG size)
{
	BOOM_PROCESS_OPERA control = { 0 };

	control.tag = TAG_READ;
	control.pid = (ULONG64)pid;
	control.address = (ULONG64)addr;
	control.buf = (ULONG64)pDataBuffer;
	control.size = size;

	RegSetValueEx(HKEY_LOCAL_MACHINE, _T(""), NULL, REG_BINARY, (byte*)&control, sizeof(control));

	return TRUE;
}

BOOL CDrvController::WriteMemory(ULONG64 pid, ULONG64 addr, PBYTE pDataBuffer, ULONG size)
{
	BOOM_PROCESS_OPERA control = { 0 };

	control.tag = TAG_WRITE;
	control.pid = (ULONG64)pid;
	control.address = (ULONG64)addr;
	control.buf = (ULONG64)pDataBuffer;
	control.size = size;

	RegSetValueEx(HKEY_LOCAL_MACHINE, _T(""), NULL, REG_BINARY, (byte*)&control, sizeof(control));

	return TRUE;
}
