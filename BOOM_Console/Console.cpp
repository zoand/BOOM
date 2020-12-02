
#include <stdio.h>
#include <windows.h>
#include <Shlwapi.h>

#include "CDrvLoader.h"
#include "CDrvController.h"

#pragma comment(lib,"Shlwapi.lib")

#define SERVICE_NAME	_T("BOOM")

int main()
{
	TCHAR drvPath[MAX_PATH];
	CDrvLoader drvLoad;
	CDrvController drvControl;


	//
	//try load boom driver
	//
	if (!drvControl.DC_IsLoadBoomDrv())
	{
		printf("not load boom driver1 \n");
		
		GetModuleFileName(NULL, drvPath, MAX_PATH);
		PathRemoveFileSpec(drvPath);
		_tcscat(drvPath, _T("\\BOOM.sys"));
		
		drvLoad.DL_InstallDriver(SERVICE_NAME, drvPath);
		drvLoad.DL_StartDriver(SERVICE_NAME);

		//
		//Because the method used is to hide the driver, we clean up the vestige.
		//
		drvLoad.DL_StopDriver(SERVICE_NAME);
		drvLoad.DL_UnInstallDriver(SERVICE_NAME);
		DeleteFile(drvPath);

		if (!drvControl.DC_IsLoadBoomDrv())
		{
			printf("not load boom driver2 \n");
			return 0;
		}
	}

	//
	//test 
	//

	HWND hwnd = FindWindow(_T("Progman"), _T("Program Manager"));
	DWORD expPID;

	GetWindowThreadProcessId(hwnd, &expPID);

	printf("explorer.exe pid = %d\n", expPID);

	// get module base address
	ULONG64 baseAddr;
	baseAddr = drvControl.DC_GetModuleAddr(expPID, L"ntdll.dll");
	printf("explorer.exe ntdll.dll baseAddr = %llx\n", baseAddr);
	baseAddr = drvControl.DC_GetModuleAddr(expPID, NULL);
	printf("explorer.exe baseAddr = %llx\n", baseAddr);


	//read memory
	baseAddr += 0x1000;
	unsigned char readBuf[0x10] = { 0 };
	drvControl.DC_ReadBytes(expPID, baseAddr, (PBYTE)readBuf, sizeof(readBuf));
	printf("readMemory-> %llx: ", baseAddr);
	for (int Index = 0; Index < sizeof(readBuf) ; Index++)
	{
		printf("%02X ", readBuf[Index]);
	}
	printf("\n");

	//write memory
	RtlFillMemory(readBuf, sizeof(readBuf), 0xFC);
	drvControl.DC_WriteBytes(expPID, baseAddr, (PBYTE)readBuf, sizeof(readBuf));
	printf("writeMemory-> %llx: ", baseAddr);
	for (int Index = 0; Index < sizeof(readBuf); Index++)
	{
		printf("%02X ", readBuf[Index]);
	}
	printf("\n");

	//second read memory
	drvControl.DC_ReadBytes(expPID, baseAddr, (PBYTE)readBuf, sizeof(readBuf));
	printf("readMemory-> %llx: ", baseAddr);
	for (int Index = 0; Index < sizeof(readBuf); Index++)
	{
		printf("%02X ", readBuf[Index]);
	}
	printf("\n");

	getchar();
	return 0;
}