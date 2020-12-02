
#include "global.h"
#include "cmpcallback.h"

LARGE_INTEGER				g_Regcookie = { 0 };

extern
PSYSTEM_ROUTINE_ADDRESS		g_pSysRotineAddr;

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

	if (Argument1 == NULL)
	{
		return STATUS_SUCCESS;
	}

	if (Argument2 == NULL)
	{
		return STATUS_SUCCESS;
	}

	NTSTATUS Status = STATUS_SUCCESS;
	REG_NOTIFY_CLASS NotifyClass;
	PREG_SET_VALUE_KEY_INFORMATION PreSetValueInfo;

	NotifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;



#if DBG
	volatile PSYSTEM_ROUTINE_ADDRESS		g_pSRA = (PSYSTEM_ROUTINE_ADDRESS)g_pSysRotineAddr;
#else
	volatile PSYSTEM_ROUTINE_ADDRESS		g_pSRA = (PSYSTEM_ROUTINE_ADDRESS)0x9090909090909090;
#endif


	PEPROCESS				process = NULL;
	PBOOM_PROCESS_OPERA		pInputData = NULL;
	PMYPEB					peb = NULL;
	KAPC_STATE				apc;
	KIRQL					kirql;
	PVOID					targetAddress = NULL;
	ULONG					targetSize = 0;
	ULONG64					cr0 = 0;
	UCHAR					probeBuf[1];
	SIZE_T					returnLenght = 0;
	BOOLEAN					attach = FALSE;

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

			//KdBreakPoint();

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
				if (NT_SUCCESS(Status) && process != NULL && g_pSRA->pfn_MmIsAddressValid((PVOID)pInputData->buf))
				{

					//
					//创建MDL来读取内存
					//

					PMDL g_pmdl = g_pSRA->pfn_IoAllocateMdl((PVOID)pInputData->buf, pInputData->size, 0, 0, NULL);
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
						attach = TRUE;
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
				if (NT_SUCCESS(Status) && process != NULL && g_pSRA->pfn_MmIsAddressValid((PVOID)pInputData->buf))
				{

					//
					//创建MDL来读取内存
					//

					PMDL g_pmdl = g_pSRA->pfn_IoAllocateMdl((PVOID)pInputData->buf, pInputData->size, 0, 0, NULL);
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
						attach = TRUE;
					}


					if (g_pSRA->pfn_MmIsAddressValid(targetAddress))
					{

						cr0 = __readcr0();
						cr0 &= 0xfffffffffffeffff;
						__writecr0(cr0);
						_disable();

						kirql = g_pSRA->pfn_KeRaiseIrqlToDpcLevel();
						g_pSRA->pfn_RtlCopyMemory(targetAddress, Mapped, targetSize);
						g_pSRA->pfn_KeLowerIrql(kirql);

						cr0 = __readcr0();
						cr0 |= 0x10000;
						_enable();
						__writecr0(cr0);

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
				if (NT_SUCCESS(Status) && process != NULL && g_pSRA->pfn_MmIsAddressValid((PVOID)pInputData->buf))
				{

					//
					//创建MDL来写内存
					//

					PMDL g_pmdl = g_pSRA->pfn_IoAllocateMdl((PVOID)pInputData->buf, pInputData->size, 0, 0, NULL);
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
						attach = TRUE;
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