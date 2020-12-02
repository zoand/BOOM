#pragma once

//
//注册表相关拦截callback，用于读写内存
//
NTSTATUS RegisterCallback(
	_In_ PVOID CallbackContext,
	_In_opt_ PVOID Argument1,
	_In_opt_ PVOID Argument2
);