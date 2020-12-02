#pragma once


#include <tchar.h>
#include <windows.h>

//
//usr atl template
//
#include <atlbase.h>
#include <atlstr.h>

class CDrvLoader
{
public:
	CDrvLoader();
	~CDrvLoader();

	//
	//得到加载驱动权限的令牌
	//
	BOOL DL_EnableDrvLoadPrivilege();

	//
	//加载驱动
	//
	BOOL DL_InstallDriver(LPCTSTR ServiceName, LPCTSTR DriverPath);

	//
	//启动驱动
	//
	BOOL DL_StartDriver(LPCTSTR ServiceName);

	//
	//停止驱动
	//
	BOOL DL_StopDriver(LPCTSTR ServiceName);

	//
	//卸载驱动
	//
	BOOL DL_UnInstallDriver(LPCTSTR ServiceName);

private:

	DWORD m_errorCode;
};

