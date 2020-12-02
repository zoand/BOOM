
#pragma once

#include <ntifs.h>
#include <intrin.h>
#include <ntimage.h>

#include "inc/inc.h"

#pragma warning(disable:4201)

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
		struct _Unkown1 {
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

//
//自定义全局数据，包含NTAPI 地址和一些数据
//
typedef struct _SYSTEM_ROUTINE_ADDRESS {
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
	fn_MmCopyVirtualMemory pfn_MmCopyVirtualMemory;
	fn_RtlInitUnicodeString pfn_RtlInitUnicodeString;
	fn_RtlCompareUnicodeString pfn_RtlCompareUnicodeString;

}SYSTEM_ROUTINE_ADDRESS, *PSYSTEM_ROUTINE_ADDRESS;