#ifndef _BOOM_SDK_H
#define _BOOM_SDK_H

void 
BO_ZwLoadDriver();

__int64 
BO_GetProcessImageBase(ULONG64 pid);

void
BO_ProtectProcess(ULONG64 pid);

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





#endif