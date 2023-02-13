#include <Windows.h>

#include <iostream>

#include <vector>
#include <fstream>
#include <psapi.h>
#include <TlHelp32.h>
#include <tchar.h>
#include "algorithm.h"





int main(void)
{
  DWORD processId = 0; 
  std::cout << "PID: "<<std::endl;
  std::cin>>processId;
  
  hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
  if (hProcess == NULL) {
    std::cout << "Failed to open process. Error code: " << GetLastError() << std::endl;
    return 1;
  }



  // Get the size of the module array
  DWORD cbNeeded;
  if (!EnumProcessModules(hProcess, NULL, 0, &cbNeeded)) {
    std::cout << "Failed to get module array size. Error code: " << GetLastError() << std::endl;

    CloseHandle(hProcess);
    return 1;
  }

  // Allocate memory for the module array
  HMODULE* hMods = new HMODULE[cbNeeded / sizeof(HMODULE)];
  if (hMods == NULL) {
    std::cout << "Failed to allocate memory for module array." << std::endl;

    CloseHandle(hProcess);
    return 1;
  }

  // Get the array of modules
  if (!EnumProcessModules(hProcess, hMods, cbNeeded, &cbNeeded)) {
    std::cout << "Failed to get module array. Error code: " << GetLastError() << std::endl;
    delete[] hMods;

    CloseHandle(hProcess);
    return 1;
  }

  // Find the .exe module
  hExeModule = NULL;
  TCHAR szModuleName[MAX_PATH];
  for (unsigned int i = 0; i < cbNeeded / sizeof(HMODULE); i++) {
    if (GetModuleFileNameEx(hProcess, hMods[i], szModuleName, sizeof(szModuleName) / sizeof(TCHAR))) {
      if (_tcsstr(szModuleName, _T(".exe"))) {
        hExeModule = hMods[i];
        break;
      }
    }
  }
  if(hExeModule)
  {
    baseAddress = hExeModule;

    MODULEINFO moduleinfo;
    GetModuleInformation(hProcess,hExeModule,&moduleinfo,sizeof(moduleinfo));


    {
        MEMORY_BASIC_INFORMATION memInfo;
        int64_t AbsoluteFunctionAddress=0x0;
        for (char *p = (char *)moduleinfo.lpBaseOfDll;p < (char *)moduleinfo.lpBaseOfDll + moduleinfo.SizeOfImage;p += memInfo.RegionSize)
        {
            SIZE_T size = VirtualQueryEx(hProcess, p, &memInfo, sizeof(memInfo));
            if (size == 0)
            {
        
                std::cerr << "VirtualQueryEx failed" << std::endl;
                return false;
                
            }
            std::size_t Regsize = memInfo.RegionSize;
            std::vector<BYTE> buffer(Regsize);

            SIZE_T bytesRead;
            if (ReadProcessMemory(hProcess, memInfo.BaseAddress, buffer.data(), Regsize, &bytesRead)/* && bytesRead == size*/)
            {
                if(auto foundaddress=Algorithm::ScanforStringRef(buffer,L"%sunreal-v%i-%s.dmp",(int64_t)memInfo.BaseAddress,3,"GetEngineVersion()"))
                {
                    if(auto CallGetEngineVersion =Algorithm::ScanFor(foundaddress,{0x48,0xFF,0xFF,0xE8},true)-0x4)
                    {
                        int32_t RelativeGetEngineVersionaddress;
                        if(ReadProcessMemory(hProcess,(void*)(CallGetEngineVersion),&RelativeGetEngineVersionaddress,4,0))
                        {
                            AbsoluteFunctionAddress = CallGetEngineVersion+RelativeGetEngineVersionaddress+0x4;
                            std::cout <<std::hex <<AbsoluteFunctionAddress<<std::endl;
                            break;
                        }
                    }
                }
               
            }
        }
    
        if(!AbsoluteFunctionAddress)
        {
            return 1;
        }
       
        BYTE CallFunction[] ={ 0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x10, 0x48, 0xB8, 0xB0, 0x48, 0xAE, 0x49, 0x01, 0x00, 0x00, 0x00, 0x48, 0x89, 0x45, 0xF8, 0x48, 0x8B, 0x45, 0xF8, 0xFF, 0xD0, 0x48, 0x89, 0x45, 0xF0, 0x48, 0x8B, 0x45, 0xF0, 0x0F, 0xB7, 0x00, 0x0F, 0xB7, 0xC0, 0x69, 0xD0, 0x10, 0x27, 0x00, 0x00, 0x48, 0x8B, 0x45, 0xF0, 0x48, 0x83, 0xC0, 0x02, 0x0F, 0xB7, 0x00, 0x0F, 0xB7, 0xC0, 0x6B, 0xC0, 0x64, 0x01, 0xC2, 0x48, 0x8B, 0x45, 0xF0, 0x48, 0x83, 0xC0, 0x04, 0x0F, 0xB7, 0x00, 0x0F, 0xB7, 0xC0, 0x01, 0xD0, 0x48, 0x98, 0xC9, 0xC3 }/*{ 0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x10, 0x48, 0xB8, 0xF0, 0x8B, 0x95, 0x40, 0x01, 0x00, 0x00, 0x00, 0x48, 0x89, 0x45, 0xF8, 0x48, 0x8B, 0x45, 0xF8, 0xFF, 0xD0, 0xC9, 0xC3 };//{0xc3,0xc9,0xff,0xd0,0xf8,0x45,0x8b,0x48,0xf8,0x45,0x89,0x48,0x00,0x00,0x00,0x01,0x49,0xae,0x48,0xb0,0xb8,0x10,0xec,0x83,0x48,0xe5,0x89,0x48,0x55}*/; //(0x149AE48B0-0x5-(DWORD64)pRemoteBuffer);
        for(int index=10;index<=17;index++)
        {
            CallFunction[index]=((AbsoluteFunctionAddress >>8*(index-10)) & 0xFF);
        }
        // Allocate memory in the target process for the function
        LPVOID pRemoteBuffer = VirtualAllocEx(hProcess, NULL, 0x1000,  MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (pRemoteBuffer == NULL)
        {
            std::cout << "Failed to allocate memory in target process. Error code: " << GetLastError() << std::endl;
            VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);
            return 1;
        }
        BOOL bWriteSuccess = WriteProcessMemory(hProcess, pRemoteBuffer, (void*)&CallFunction, sizeof(CallFunction), NULL);
        if (!bWriteSuccess)
        {
            std::cout << "Failed to write function to target process. Error code: " << GetLastError() << std::endl;
            VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);
          
            return 1;
        }

        // Create a remote thread in the target process to execute the function
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)(pRemoteBuffer), NULL, 0, NULL);
        if (hThread == NULL)
        {
            std::cout << "Failed to create remote thread in target process. Error code: " << GetLastError() << std::endl;
            VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);
           
            return 1;
        }

        DWORD dwWaitResult = WaitForSingleObject(hThread, INFINITE);
        if (dwWaitResult != WAIT_OBJECT_0)
        {
            std::cout << "Failed to wait for remote thread to complete. Error code: " << GetLastError() << std::endl;
            VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);

            CloseHandle(hThread);

            return 1;
        }

        DWORD dwExitCode;
        BOOL bReadSuccess =GetExitCodeThread(hThread,&dwExitCode);
        if (!bReadSuccess)
        {
            std::cout << "Failed to read return value of function from target process. Error code: " << GetLastError() << std::endl;
            VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);

            CloseHandle(hThread);

            return 1;
        }


        std::cout << "Engine Version " <<std::dec << (int)dwExitCode << std::endl;


        VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);

        CloseHandle(hThread);








      
    }
  }
  delete[] hMods;

  CloseHandle(hProcess);
  system("pause");
  return 1;
}
