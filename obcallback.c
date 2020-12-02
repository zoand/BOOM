
#include "global.h"
#include "obcallback.h"

PVOID						g_obHandle = NULL;

extern
PSYSTEM_ROUTINE_ADDRESS		g_pSysRotineAddr;

//
//bypass objecthook签名
//
void BypassCheckSign(
	_In_ PDRIVER_OBJECT pDriverObj)
{
	//STRUCT FOR WIN64
	typedef struct _LDR_DATA                         			// 24 elements, 0xE0 bytes (sizeof)
	{
		LIST_ENTRY64 InLoadOrderLinks;
		LIST_ENTRY64 InMemoryOrderLinks;
		LIST_ENTRY64 InInitializationOrderLinks;
		ULONG64 DllBase;
		ULONG64 EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		ULONG   Flags;
	}LDR_DATA, *PLDR_DATA;
	PLDR_DATA ldr;
	ldr = (PLDR_DATA)(pDriverObj->DriverSection);
	ldr->Flags |= 0x20;
}

//
//保护进程
//
NTSTATUS ObRegiserCllabck(
	_In_ PVOID ObjectCllbackAddr)
{
	NTSTATUS	status;
	OB_CALLBACK_REGISTRATION obReg;
	OB_OPERATION_REGISTRATION opReg;

	memset(&obReg, 0, sizeof(obReg));
	obReg.Version = ObGetFilterVersion();
	obReg.OperationRegistrationCount = 1;
	obReg.RegistrationContext = NULL;
	RtlInitUnicodeString(&obReg.Altitude, L"354156");
	obReg.OperationRegistration = &opReg;
	memset(&opReg, 0, sizeof(opReg));
	opReg.ObjectType = PsProcessType;
	opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	opReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)ObjectCllbackAddr;
	status = ObRegisterCallbacks(&obReg, &g_obHandle);

	return status;
}


//
//进程保护callback
//
OB_PREOP_CALLBACK_STATUS ObPreopCallback(
	_In_ PVOID RegistrationContext,
	_In_ POB_PRE_OPERATION_INFORMATION pOperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);

	if (pOperationInformation == NULL || pOperationInformation->Object == NULL)
	{
		return OB_PREOP_SUCCESS;
	}

#if DBG
	volatile PSYSTEM_ROUTINE_ADDRESS		g_pSRA = (PSYSTEM_ROUTINE_ADDRESS)g_pSysRotineAddr;
#else
	volatile PSYSTEM_ROUTINE_ADDRESS		g_pSRA = (PSYSTEM_ROUTINE_ADDRESS)0x9090909090909090;
#endif

	HANDLE pid = g_pSRA->pfn_PsGetProcessId((PEPROCESS)pOperationInformation->Object);

	if (g_pSRA->ProtectPid == pid)
	{
		if (pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE)
		{
			if (pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess & PROCESS_TERMINATE)
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= (~PROCESS_TERMINATE);
			if (pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess & PROCESS_VM_OPERATION)
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= (~PROCESS_VM_OPERATION);
			if (pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess & PROCESS_VM_READ)
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= (~PROCESS_VM_READ);
			if (pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess & PROCESS_VM_WRITE)
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= (~PROCESS_VM_WRITE);
			if (pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess & PROCESS_SUSPEND_RESUME)
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= (~PROCESS_SUSPEND_RESUME);

		}
		if (pOperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE)
		{
			if (pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess & PROCESS_TERMINATE)
				pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= (~PROCESS_TERMINATE);
			if (pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess & PROCESS_VM_OPERATION)
				pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= (~PROCESS_VM_OPERATION);
			if (pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess & PROCESS_VM_READ)
				pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= (~PROCESS_VM_READ);
			if (pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess & PROCESS_VM_WRITE)
				pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= (~PROCESS_VM_WRITE);
			if (pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess & PROCESS_SUSPEND_RESUME)
				pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess &= (~PROCESS_SUSPEND_RESUME);
		}
	}

	return OB_PREOP_SUCCESS;
}