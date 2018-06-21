
#include "ntifs.h"
#include "utils.h"
#include "intrin.h"

#include "regStruct.h"
#include "./BOOM_Console/BoomDef.h"


//
//全局数据 内存标记
//
#define TAG_SYSTEMROUTINE	'rsys'
#define TAG_SHELLCODE		'dcls'
#define TAG_SHELLCODE_POBJ	'jbop'

//
//内存操作flasg
//
#define PROCESS_TERMINATE                  (0x0001)  
#define PROCESS_CREATE_THREAD              (0x0002)  
#define PROCESS_SET_SESSIONID              (0x0004)  
#define PROCESS_VM_OPERATION               (0x0008)  
#define PROCESS_VM_READ                    (0x0010)  
#define PROCESS_VM_WRITE                   (0x0020)  
#define PROCESS_DUP_HANDLE                 (0x0040)  
#define PROCESS_CREATE_PROCESS             (0x0080)  
#define PROCESS_SET_QUOTA                  (0x0100)  
#define PROCESS_SET_INFORMATION            (0x0200)  
#define PROCESS_QUERY_INFORMATION          (0x0400)  
#define PROCESS_SUSPEND_RESUME             (0x0800)  
#define PROCESS_QUERY_LIMITED_INFORMATION  (0x1000)  
#define PROCESS_SET_LIMITED_INFORMATION    (0x2000)  

//
//系统模块链表
//
typedef struct _LDR_DATA_TABLE_ENTRY64 {
	LIST_ENTRY64 InLoadOrderLinks;
	LIST_ENTRY64 InMemoryOrderLinks;
	LIST_ENTRY64 InInitializationOrderLinks;
	ULONG64 DllBase;
	ULONG64 EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG   Flags;
	USHORT  LoadCount;
	USHORT TlsIndex;
	union {
		LIST_ENTRY64 HashLinks;
		struct _Unkown1{
			ULONG64 SectionPointer;
			ULONG   CheckSum;
		};
	};
	union {
		ULONG   TimeDateStamp;
		ULONG64 LoadedImports;

	};

	//
	// NOTE : Do not grow this structure at the dump files used a packed
	// array of these structures.
	//

} LDR_DATA_TABLE_ENTRY64, *PLDR_DATA_TABLE_ENTRY64;

//
//自定义PEB结构
//
typedef struct _MYPEB
{
	union
	{
		struct dummy00
		{
			UCHAR InheritedAddressSpace;
			UCHAR ReadImageFileExecOptions;
			UCHAR BeingDebugged;
			UCHAR BitField;
		};
		PVOID dummy01;
	};

	PVOID Mutant;
	PVOID ImageBaseAddress;
	PVOID Ldr;
	PVOID ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	PVOID CrossProcessFlags;
	PVOID KernelCallbackTable;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
} MYPEB, *PMYPEB;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	ULONG Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID	EntryInProgress;
	ULONG	ShutdownInProgress;
	PVOID	ShutdownThreadId;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	union
	{
		ULONG SizeOfImage;
		PVOID dummy01;
	};
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;

} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

#ifdef __cplusplus    
extern "C"
{
#endif    
	NTKERNELAPI
		NTSTATUS
		ObReferenceObjectByName(
		IN PUNICODE_STRING ObjectName,
		IN ULONG Attributes,
		IN PACCESS_STATE PassedAccessState OPTIONAL,
		IN ACCESS_MASK DesiredAccess OPTIONAL,
		IN POBJECT_TYPE ObjectType,
		IN KPROCESSOR_MODE AccessMode,
		IN OUT PVOID ParseContext OPTIONAL,
		OUT PVOID *Object
		);
	extern POBJECT_TYPE *IoDriverObjectType;
#ifdef __cplusplus    
}
#endif    

//
//自己定义NTAPI，用于shellcode动态调用
//
typedef HANDLE(NTAPI *fn_PsGetCurrentProcessId)(
VOID
);

typedef NTSTATUS(NTAPI *fn_PsLookupProcessByProcessId)(
_In_ HANDLE ProcessId,
_Outptr_ PEPROCESS *Process
);

typedef BOOLEAN(NTAPI *fn_MmIsAddressValid)(
_In_ PVOID VirtualAddress
);

typedef PMDL(NTAPI *fn_IoAllocateMdl)(
_In_opt_ __drv_aliasesMem PVOID VirtualAddress,
_In_ ULONG Length,
_In_ BOOLEAN SecondaryBuffer,
_In_ BOOLEAN ChargeQuota,
_Inout_opt_ PIRP Irp
);

typedef VOID(NTAPI *fn_MmBuildMdlForNonPagedPool)(
_Inout_ PMDL MemoryDescriptorList
);

typedef PVOID(NTAPI *fn_MmMapLockedPages)(
_Inout_ PMDL MemoryDescriptorList,
_In_ __drv_strictType(KPROCESSOR_MODE / enum _MODE, __drv_typeConst)
KPROCESSOR_MODE AccessMode
);

typedef VOID(NTAPI *fn_IoFreeMdl)(
PMDL Mdl
);

typedef PEPROCESS(NTAPI *fn_PsGetCurrentProcess)(
VOID
);

typedef VOID(NTAPI *fn_KeStackAttachProcess)(
_Inout_ PRKPROCESS PROCESS,
_Out_ PRKAPC_STATE ApcState
);

typedef KIRQL(NTAPI *fn_KeRaiseIrqlToDpcLevel)(
	VOID
	);

typedef VOID(NTAPI *fn_RtlCopyMemory)(
	void *Dst,
	const void *Src,
	size_t Size);

typedef VOID(NTAPI *fn_KeLowerIrql)(
_In_ _Notliteral_ _IRQL_restores_ KIRQL NewIrql
);

typedef VOID(NTAPI *fn_KeUnstackDetachProcess)(
_In_ PRKAPC_STATE ApcState
);

typedef VOID(NTAPI *fn_MmUnmapLockedPages)(
_In_ PVOID BaseAddress,
_Inout_ PMDL MemoryDescriptorList
);

typedef LONG_PTR(NTAPI *fn_ObDereferenceObject)(
_In_ PVOID Object
);

typedef PVOID(NTAPI *fn_PsGetProcessWow64Process)(
	IN PEPROCESS Process);

typedef PMYPEB(NTAPI *fn_PsGetProcessPeb)(
	IN PEPROCESS Process);

typedef HANDLE(NTAPI* fn_PsGetProcessId)(
	_In_ PEPROCESS Process
	);

typedef VOID(NTAPI *fn_MmUnlockPages)(
_Inout_ PMDL MemoryDescriptorList
);

typedef VOID(NTAPI* fn_MmProbeAndLockPages)(
_Inout_ PMDL MemoryDescriptorList,
_In_ KPROCESSOR_MODE AccessMode,
_In_ LOCK_OPERATION Operation
);

typedef KIRQL(NTAPI *fn_KeGetCurrentIrql)(
	VOID);

typedef NTSTATUS(NTAPI* fn_MmCopyVirtualMemory)(
IN PEPROCESS FromProcess,
IN CONST VOID *FromAddress,
IN PEPROCESS ToProcess,
OUT PVOID ToAddress,
IN SIZE_T BufferSize,
IN KPROCESSOR_MODE PreviousMode,
OUT PSIZE_T NumberOfBytesCopied
);

typedef VOID(NTAPI* fn_RtlInitUnicodeString)(
PUNICODE_STRING DestinationString,
PCWSTR SourceString
);

typedef LONG(NTAPI* fn_RtlCompareUnicodeString)(
_In_ PCUNICODE_STRING String1,
_In_ PCUNICODE_STRING String2,
_In_ BOOLEAN CaseInSensitive
);

typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation, // MEMORY_BASIC_INFORMATION
	MemoryWorkingSetInformation, // MEMORY_WORKING_SET_INFORMATION
	MemoryMappedFilenameInformation, // UNICODE_STRING
	MemoryRegionInformation, // MEMORY_REGION_INFORMATION
	MemoryWorkingSetExInformation, // MEMORY_WORKING_SET_EX_INFORMATION
	MemorySharedCommitInformation, // MEMORY_SHARED_COMMIT_INFORMATION
	MemoryImageInformation, // MEMORY_IMAGE_INFORMATION
	MemoryRegionInformationEx,
	MemoryPrivilegedBasicInformation
} MEMORY_INFORMATION_CLASS;

typedef struct _MEMORY_BASIC_INFORMATION {
	PVOID BaseAddress;
	PVOID AllocationBase;
	DWORD AllocationProtect;
	SIZE_T RegionSize;
	DWORD State;
	DWORD Protect;
	DWORD Type;
} MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;

typedef
NTSTATUS
(NTAPI*fn_NtQueryVirtualMemory)(
_In_ HANDLE ProcessHandle,
_In_ PVOID BaseAddress,
_In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
_Out_ PVOID MemoryInformation,
_In_ SIZE_T MemoryInformationLength,
_Out_opt_ PSIZE_T ReturnLength
);

//
//自定义全局数据，包含NTAPI 地址和一些数据
//
typedef struct _SYSTEM_ROUTINE_ADDRESS{
	HANDLE			ProtectPid;
	ULONG64			tag;
	ULONG64			flags;
	fn_PsGetCurrentProcessId pfn_PsGetCurrentProcessId;
	fn_PsLookupProcessByProcessId pfn_PsLookupProcessByProcessId;
	fn_MmIsAddressValid pfn_MmIsAddressValid;
	fn_IoAllocateMdl pfn_IoAllocateMdl;
	fn_MmBuildMdlForNonPagedPool pfn_MmBuildMdlForNonPagedPool;
	fn_MmMapLockedPages pfn_MmMapLockedPages;
	fn_IoFreeMdl pfn_IoFreeMdl;
	fn_PsGetCurrentProcess pfn_PsGetCurrentProcess;
	fn_KeStackAttachProcess pfn_KeStackAttachProcess;
	fn_KeRaiseIrqlToDpcLevel pfn_KeRaiseIrqlToDpcLevel;
	fn_RtlCopyMemory pfn_RtlCopyMemory;
	fn_KeLowerIrql pfn_KeLowerIrql;
	fn_KeUnstackDetachProcess pfn_KeUnstackDetachProcess;
	fn_MmUnmapLockedPages pfn_MmUnmapLockedPages;
	fn_ObDereferenceObject pfn_ObDereferenceObject;
	fn_PsGetProcessWow64Process pfn_PsGetProcessWow64Process;
	fn_PsGetProcessPeb pfn_PsGetProcessPeb;
	fn_PsGetProcessId pfn_PsGetProcessId;
	fn_MmUnlockPages pfn_MmUnlockPages;
	fn_MmProbeAndLockPages pfn_MmProbeAndLockPages;
	fn_KeGetCurrentIrql pfn_KeGetCurrentIrql;
	fn_NtQueryVirtualMemory pfn_NtQueryVirtualMemory;
	fn_MmCopyVirtualMemory pfn_MmCopyVirtualMemory;
	fn_RtlInitUnicodeString pfn_RtlInitUnicodeString;
	fn_RtlCompareUnicodeString pfn_RtlCompareUnicodeString;

}SYSTEM_ROUTINE_ADDRESS, *PSYSTEM_ROUTINE_ADDRESS;

//
//全局变量
//
static
LARGE_INTEGER				g_Regcookie = {0};

static
PSYSTEM_ROUTINE_ADDRESS		g_pSysRotineAddr = NULL;

static
PVOID						g_shellcode = NULL;

static
PVOID						g_shellcode_pobj = NULL;

static
PVOID						g_obHandle = NULL;

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
		ExFreePoolWithTag(g_pSysRotineAddr, TAG_SYSTEMROUTINE);
	
	if (g_shellcode)
		ExFreePoolWithTag(g_shellcode, TAG_SHELLCODE);

	if (g_shellcode_pobj)
		ExFreePoolWithTag(g_shellcode_pobj, TAG_SHELLCODE_POBJ);
	
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
//注册表相关拦截callback，用于读写内存
//
NTSTATUS RegisterCallback(
	_In_ PVOID CallbackContext,
	_In_opt_ PVOID Argument1,
	_In_opt_ PVOID Argument2
	)
{
	UNREFERENCED_PARAMETER(CallbackContext);


	NTSTATUS Status = STATUS_SUCCESS;
	REG_NOTIFY_CLASS NotifyClass;
	PREG_SET_VALUE_KEY_INFORMATION PreSetValueInfo;

	NotifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

	if (Argument2 == NULL) 
	{
		return STATUS_SUCCESS;
	}

#if DBG
	PSYSTEM_ROUTINE_ADDRESS		g_pSRA = (PSYSTEM_ROUTINE_ADDRESS)g_pSysRotineAddr;
#else
	PSYSTEM_ROUTINE_ADDRESS		g_pSRA = (PSYSTEM_ROUTINE_ADDRESS)0x9090909090909090;
#endif


	PEPROCESS				process = NULL;
	PBOOM_PROCESS_OPERA		pInputData = NULL;
	PMYPEB					peb = NULL;
	KAPC_STATE				apc;
	KIRQL					kirql = NULL;
	PVOID					targetAddress = NULL;
	ULONG					targetSize = 0;
	ULONG64					cr0 = 0;
	UCHAR					probeBuf[1];
	SIZE_T					returnLenght =0;
	bool					attach = false;

	switch (NotifyClass)
	{
	case RegNtPreSetValueKey:
	{
		PreSetValueInfo = (PREG_SET_VALUE_KEY_INFORMATION)Argument2;

		if (PreSetValueInfo->Type == REG_BINARY &&
			PreSetValueInfo->DataSize == sizeof(BOOM_PROCESS_OPERA))
		{

			pInputData = (PBOOM_PROCESS_OPERA)PreSetValueInfo->Data;

			//
			//debugBreak
			//

			KdBreakPoint();

			if (g_pSRA->pfn_KeGetCurrentIrql() != PASSIVE_LEVEL)
			{
				return STATUS_SUCCESS;
			}

			switch (pInputData->tag)
			{
			case TAG_READ:
			{
				//
				//校验参数是否正确
				//

				Status = g_pSRA->pfn_PsLookupProcessByProcessId((HANDLE)pInputData->pid, &process);
				if (NT_SUCCESS(Status) && process != NULL && g_pSRA->pfn_MmIsAddressValid(pInputData->buf))
				{

					//
					//创建MDL来读取内存
					//

					PMDL g_pmdl = g_pSRA->pfn_IoAllocateMdl(pInputData->buf, pInputData->size, 0, 0, NULL);
					if (!g_pmdl)
						break;
					g_pSRA->pfn_MmBuildMdlForNonPagedPool(g_pmdl);
					unsigned char* Mapped = (unsigned char*)g_pSRA->pfn_MmMapLockedPages(g_pmdl, KernelMode);
					if (!Mapped)
					{
						g_pSRA->pfn_IoFreeMdl(g_pmdl);
						break;
					}

					//
					//attach上去的时候保存 读取目标地址和大小
					//

					targetAddress = (PVOID)pInputData->address;
					targetSize = pInputData->size;

					if (g_pSRA->pfn_PsGetCurrentProcess() != process)
					{
						g_pSRA->pfn_KeStackAttachProcess(process, &apc);
						attach = true;
					}

					//
					//读内存
					//
						
					if (g_pSRA->pfn_MmIsAddressValid(targetAddress))
					{

						kirql = g_pSRA->pfn_KeRaiseIrqlToDpcLevel();
						g_pSRA->pfn_RtlCopyMemory(Mapped, targetAddress, targetSize);
						g_pSRA->pfn_KeLowerIrql(kirql);
					}

					if (attach)
					{
						g_pSRA->pfn_KeUnstackDetachProcess(&apc);
					}

					g_pSRA->pfn_MmUnmapLockedPages((PVOID)Mapped, g_pmdl);
					g_pSRA->pfn_IoFreeMdl(g_pmdl);

				}

				break;
			}
			case TAG_WRITE:
			{

				//
				//校验参数是否正确
				//

				Status = g_pSRA->pfn_PsLookupProcessByProcessId((HANDLE)pInputData->pid, &process);
				if (NT_SUCCESS(Status) && process != NULL && g_pSRA->pfn_MmIsAddressValid(pInputData->buf))
				{

					//
					//创建MDL来读取内存
					//

					PMDL g_pmdl = g_pSRA->pfn_IoAllocateMdl(pInputData->buf, pInputData->size, 0, 0, NULL);
					if (!g_pmdl)
						break;
					g_pSRA->pfn_MmBuildMdlForNonPagedPool(g_pmdl);
					

					unsigned char* Mapped = (unsigned char*)g_pSRA->pfn_MmMapLockedPages(g_pmdl, KernelMode);
					if (!Mapped)
					{
						g_pSRA->pfn_IoFreeMdl(g_pmdl);
						break;
					}

					//
					//attach上去的时候保存 读取目标地址和大小
					//

					targetAddress = (PVOID)pInputData->address;
					targetSize = pInputData->size;

					if (g_pSRA->pfn_PsGetCurrentProcess() != process)
					{
						g_pSRA->pfn_KeStackAttachProcess(process, &apc);
						attach = true;
					}


					if (g_pSRA->pfn_MmIsAddressValid(targetAddress))
					{

						kirql = g_pSRA->pfn_KeRaiseIrqlToDpcLevel();
						cr0 = __readcr0();
						cr0 &= 0xfffffffffffeffff;
						__writecr0(cr0);
						_disable();

						g_pSRA->pfn_RtlCopyMemory(targetAddress, Mapped, targetSize);
						g_pSRA->pfn_KeLowerIrql(kirql);

						cr0 = __readcr0();
						cr0 |= 0x10000;
						_enable();
						__writecr0(cr0);
						g_pSRA->pfn_KeLowerIrql(kirql);

					}

					if (attach)
					{
						g_pSRA->pfn_KeUnstackDetachProcess(&apc);
					}
					
					g_pSRA->pfn_MmUnmapLockedPages((PVOID)Mapped, g_pmdl);
					g_pSRA->pfn_IoFreeMdl(g_pmdl);
					
					
				}
				break;
			}
			case TAG_GETMODULE:
			{
				//
				//校验参数是否正确
				//

				Status = g_pSRA->pfn_PsLookupProcessByProcessId((HANDLE)pInputData->pid, &process);
				if (NT_SUCCESS(Status) && process != NULL && g_pSRA->pfn_MmIsAddressValid(pInputData->buf))
				{

					//
					//创建MDL来写内存
					//

					PMDL g_pmdl = g_pSRA->pfn_IoAllocateMdl(pInputData->buf, pInputData->size, 0, 0, NULL);
					if (!g_pmdl)
						break;
					g_pSRA->pfn_MmBuildMdlForNonPagedPool(g_pmdl);
					unsigned char* Mapped = (unsigned char*)g_pSRA->pfn_MmMapLockedPages(g_pmdl, KernelMode);
					if (!Mapped)
					{
						g_pSRA->pfn_IoFreeMdl(g_pmdl);
						break;
					}

					//
					//attach上去
					//

					if (g_pSRA->pfn_PsGetCurrentProcess() != process)
					{
						g_pSRA->pfn_KeStackAttachProcess(process, &apc);
						attach = true;
					}

					//
					//判断是否64位进程
					//
					if (g_pSRA->pfn_PsGetProcessWow64Process(process) == NULL)
					{
						peb = g_pSRA->pfn_PsGetProcessPeb(process);
						if (peb != NULL)
						{
							if (Mapped[0] == '\0') //传空则获取 exe->ImageBaseAddress 基址
							{
								kirql = g_pSRA->pfn_KeRaiseIrqlToDpcLevel();
								g_pSRA->pfn_RtlCopyMemory(Mapped, &peb->ImageBaseAddress, sizeof(PVOID));
								g_pSRA->pfn_KeLowerIrql(kirql);
							}
							else
							{
								PPEB_LDR_DATA	pPebLdrData = (PPEB_LDR_DATA)peb->Ldr;
								PLIST_ENTRY		pListEntryStart = NULL;
								PLIST_ENTRY		pListEntryEnd = NULL;

								PLDR_DATA_TABLE_ENTRY pLdrDataEntry = NULL;

								UNICODE_STRING	queryModuleName;
								g_pSRA->pfn_RtlInitUnicodeString(&queryModuleName, (PCWSTR)Mapped);

								pListEntryStart = pListEntryEnd = pPebLdrData->InMemoryOrderModuleList.Blink;

								do
								{

									pLdrDataEntry = (PLDR_DATA_TABLE_ENTRY)CONTAINING_RECORD(pListEntryStart, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

									if (g_pSRA->pfn_RtlCompareUnicodeString(&pLdrDataEntry->BaseDllName, &queryModuleName, TRUE) == 0)
									{
										kirql = g_pSRA->pfn_KeRaiseIrqlToDpcLevel();
										g_pSRA->pfn_RtlCopyMemory(Mapped, &pLdrDataEntry->DllBase, sizeof(PVOID));
				
										g_pSRA->pfn_KeLowerIrql(kirql);
										break;
									}

									pListEntryStart = pListEntryStart->Blink;

								} while (pListEntryStart != pListEntryEnd);


							}
						}
					}
					
					if (attach)
					{
						g_pSRA->pfn_KeUnstackDetachProcess(&apc);
					}

					g_pSRA->pfn_MmUnmapLockedPages((PVOID)Mapped, g_pmdl);
					g_pSRA->pfn_IoFreeMdl(g_pmdl);

				}

				break;
			}
			case TAG_PROTECT:
			{
				g_pSRA->ProtectPid = (HANDLE)pInputData->pid;
				break;
			}
			case TAG_PROBEREAD:
			{
				Status = g_pSRA->pfn_PsLookupProcessByProcessId((HANDLE)pInputData->pid, &process);
				if (NT_SUCCESS(Status) && process != NULL)
				{
					g_pSRA->pfn_MmCopyVirtualMemory(process,
													(PVOID)pInputData->address,
													g_pSRA->pfn_PsGetCurrentProcess(),
													probeBuf,
													sizeof(probeBuf),
													KernelMode,
													&returnLenght);
				
				}
			break;
			}
			default:
				break;
			}

			if (process != NULL)
			{
				g_pSRA->pfn_ObDereferenceObject(process);
			}
			Status = STATUS_UNSUCCESSFUL;

		}
		break;
	}
	default:
		break;
	}

	return Status;

}

//
//进程保护callback
//
OB_PREOP_CALLBACK_STATUS preCall(
	_In_ PVOID RegistrationContext,
	_In_ POB_PRE_OPERATION_INFORMATION pOperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);

	if (pOperationInformation == NULL || pOperationInformation->Object == NULL)
	{
		return OB_PREOP_SUCCESS;
	}

#if DBG
	PSYSTEM_ROUTINE_ADDRESS		g_pSRA = (PSYSTEM_ROUTINE_ADDRESS)g_pSysRotineAddr;
#else
	PSYSTEM_ROUTINE_ADDRESS		g_pSRA = (PSYSTEM_ROUTINE_ADDRESS)0x9090909090909090;
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
	bool				bFinded = false;

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

	__try{
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
		0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
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
			bFinded = true;
			break;
		}
		pSecHead++;
	}

	//
	//没有找到PAGE 页面
	//

	if (!bFinded)
	{
		KdPrint(("[BOOM] not find to name PAGE in the section.\n"));
		return NULL;
	}

	//
	//妈的 这么6？
	//

	if (pSecHead->Misc.VirtualSize % PAGE_SIZE == 0)
	{
		KdPrint(("[BOOM] PAGE virtual size not align space.\n"));
		return NULL;
	}

	AlignPageSize = ((pSecHead->Misc.VirtualSize / PAGE_SIZE) + 1) * PAGE_SIZE;

	cResult1 = AlignPageSize - pSecHead->Misc.VirtualSize;
	cResult2 = count * 16;
	if (cResult1 < cResult2)
	{
		KdPrint(("[BOOM] PAGE virtual size algin space not enough.\n"));
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

	memcpy(&hookCode[6], &address, sizeof(PVOID));

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
		(PSYSTEM_ROUTINE_ADDRESS)ExAllocatePoolWithTag(NonPagedPool, sizeof(SYSTEM_ROUTINE_ADDRESS), TAG_SYSTEMROUTINE);
	if (g_pSysRotineAddr == NULL)
	{
		return status;
	}
	g_pSysRotineAddr->ProtectPid = (HANDLE)-1;

	RtlInitUnicodeString(&routineName,L"PsGetCurrentProcessId");
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
//保护进程
//
NTSTATUS ProtectProcess(
	_In_ PVOID ObjectCllbackAddr)
{
	NTSTATUS	status;
	OB_CALLBACK_REGISTRATION obReg;
	OB_OPERATION_REGISTRATION opReg;

	memset(&obReg, 0, sizeof(obReg));
	obReg.Version = ObGetFilterVersion();
	obReg.OperationRegistrationCount = 1;
	obReg.RegistrationContext = NULL;
	RtlInitUnicodeString(&obReg.Altitude, L"326611");
	obReg.OperationRegistration = &opReg;
	memset(&opReg, 0, sizeof(opReg));
	opReg.ObjectType = PsProcessType;
	opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	opReg.PreOperation = (POB_PRE_OPERATION_CALLBACK)ObjectCllbackAddr;
	status = ObRegisterCallbacks(&obReg, &g_obHandle);

	return status;
}

//
//驱动入口
//
extern "C"
NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING  RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS	status;
	PVOID		FakeCallback, FakeCallback2;
	PUCHAR		pRepRoutinePoint;
	UNICODE_STRING	altitude;
	UNICODE_STRING	fakeDrv;
	UNICODE_STRING	DeviceName;

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

	g_shellcode = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, TAG_SHELLCODE);
	if (!g_shellcode)
	{
		status = STATUS_MEMORY_NOT_ALLOCATED;
		goto __exit;
	}
	RtlSuperCopyMemory(g_shellcode, RegisterCallback, PAGE_SIZE);

	pRepRoutinePoint = (PUCHAR)g_shellcode;
	for (int i = 0; i < PAGE_SIZE - sizeof(ULONG64); i++)
	{
		if (pRepRoutinePoint[i] == 0x90 && 
			*(ULONG64*)(&pRepRoutinePoint[i]) == 0x9090909090909090)
		{
			PVOID	fined = &pRepRoutinePoint[i];
			RtlSuperCopyMemory(fined, &g_pSysRotineAddr, sizeof(g_pSysRotineAddr));
			
		}
	}
	//object hook
	g_shellcode_pobj = ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, TAG_SHELLCODE_POBJ);
	if (!g_shellcode_pobj)
	{
		status = STATUS_MEMORY_NOT_ALLOCATED;
		goto __exit;
	}
	RtlSuperCopyMemory(g_shellcode_pobj, preCall, PAGE_SIZE);

	pRepRoutinePoint = (PUCHAR)g_shellcode_pobj;
	for (int i = 0; i < PAGE_SIZE - sizeof(ULONG64); i++)
	{
		if (pRepRoutinePoint[i] == 0x90 &&
			*(ULONG64*)(&pRepRoutinePoint[i]) == 0x9090909090909090)
		{
			PVOID	fined = &pRepRoutinePoint[i];
			RtlSuperCopyMemory(fined, &g_pSysRotineAddr, sizeof(g_pSysRotineAddr));

		}
	}

	//
	//枚举其他驱动做跳板代码
	//
	RtlInitUnicodeString(&fakeDrv, L"Beep.SYS");
	FakeCallback = EnumJumpDrv(DriverObject, &fakeDrv,g_shellcode, 1);
	
	FakeCallback2 = EnumJumpDrv(DriverObject, &fakeDrv, g_shellcode_pobj, 2);

#ifndef DBG
	if (FakeCallback == NULL || FakeCallback2 == NULL)
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
	ProtectProcess(preCall);
#else
	ProtectProcess(FakeCallback2);
#endif

	//
	//注册注册表回调
	//

	RtlInitUnicodeString(&altitude, L"466010");
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
		return 0xC0000088;
#endif
	}

__exit:
	if (g_pSysRotineAddr)
		ExFreePoolWithTag(g_pSysRotineAddr, TAG_SYSTEMROUTINE);
	if (g_shellcode)
		ExFreePoolWithTag(g_shellcode, TAG_SHELLCODE);
	if (g_shellcode_pobj)
		ExFreePoolWithTag(g_shellcode_pobj, TAG_SHELLCODE_POBJ);

	return status;

}
