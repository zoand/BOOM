#pragma once


//
//bypass objecthook签名
//
void BypassCheckSign(
	_In_ PDRIVER_OBJECT pDriverObj);
//
//注册callback
//
NTSTATUS ObRegiserCllabck(
	_In_ PVOID ObjectCllbackAddr);


//
//进程保护callback
//
OB_PREOP_CALLBACK_STATUS ObPreopCallback(
	_In_ PVOID RegistrationContext,
	_In_ POB_PRE_OPERATION_INFORMATION pOperationInformation);