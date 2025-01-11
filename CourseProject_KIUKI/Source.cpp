#include <Windows.h>
#include <iostream>

typedef char* (*RetrieveFileAccessMaskByPathProc)(const char*);
typedef char* (*RetrieveFileAccessMaskByHandleProc)(HANDLE);
typedef char* (*RetrieveKernelObjAccessMaskProc)(HANDLE);

int main() {
  HMODULE hModule = LoadLibrary(L"AccessMaskProcessor.dll");
  if (hModule == NULL) {
    std::wcerr << L"Failed to load DLL!" << std::endl;
    return 1;
  }

  //  --------------------------------------------------------------

  RetrieveFileAccessMaskByPathProc RetrieveFileAccessMaskByPath = (RetrieveFileAccessMaskByPathProc)GetProcAddress(hModule, "RetrieveFileAccessInfoByPath");
  if (RetrieveFileAccessMaskByPath == NULL) {
    std::wcerr << L"Failed to find function!" << std::endl;
    FreeLibrary(hModule);
    return 1;
  }

  const char* filePath = "C:/Users/Queue/Downloads/Reterraforged-Mod-Forge-1.20.1.jar";
  char* result1 = RetrieveFileAccessMaskByPath(filePath);
  std::cout << "FILE by PATH: " << filePath << std::endl << result1 << std::endl;
  delete[] result1;

  //  --------------------------------------------------------------

  RetrieveFileAccessMaskByHandleProc RetrieveFileAccessMaskByHandle = (RetrieveFileAccessMaskByHandleProc)GetProcAddress(hModule, "RetrieveFileAccessInfoByHandle");
  if (RetrieveFileAccessMaskByHandle == NULL) {
    std::wcerr << L"Failed to find function!" << std::endl;
    FreeLibrary(hModule);
    return 1;
  }

  HANDLE hFile = CreateFileA("C:/Users/Queue/Downloads/Reterraforged-Mod-Forge-1.20.1.jar", GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hFile == INVALID_HANDLE_VALUE) {
    std::cerr << "Failed to open file!" << std::endl;
    return 1;
  }

  char* result2 = RetrieveFileAccessMaskByHandle(hFile);
  std::cout << "FILE by HANDLE: " << filePath << std::endl << result2 << std::endl;
  delete[] result2;
  CloseHandle(hFile);

  //  --------------------------------------------------------------

  RetrieveKernelObjAccessMaskProc RetrieveKernelObjAccessMask = (RetrieveKernelObjAccessMaskProc)GetProcAddress(hModule, "RetrieveKernelObjAccessInfo");
  if (RetrieveKernelObjAccessMask == NULL) {
    std::wcerr << L"Failed to find function!" << std::endl;
    FreeLibrary(hModule);
    return 1;
  }

  HANDLE hMutex = CreateMutexA(NULL, FALSE, "MyTestMutex");
  if (hMutex == NULL) {
    std::cerr << "Failed to create mutex!" << std::endl;
    return 1;
  }

  char* result3 = RetrieveKernelObjAccessMask(hMutex);
  std::cout << "MUTEX:\n" << result3 << std::endl;
  delete[] result3;
  CloseHandle(hMutex);

  // --------------------------------------------------------------

  HANDLE hSemaphore = CreateSemaphoreA(NULL, 1, 1, "MyTestSemaphore");
  if (hSemaphore == NULL) {
    std::cerr << "Failed to create semaphore!" << std::endl;
    return 1;
  }

  char* result4 = RetrieveKernelObjAccessMask(hSemaphore);
  std::cout << "SEMAPHORE:\n" << result4 << std::endl;
  delete[] result4;
  CloseHandle(hSemaphore);

  // --------------------------------------------------------------

  HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
  if (hProcess == NULL) {
    std::cerr << "Failed to open process!" << std::endl;
    return 1;
  }

  char* result5 = RetrieveKernelObjAccessMask(hProcess);
  std::cout << "PROCESS:\n" << result5 << std::endl;
  delete[] result5;
  CloseHandle(hProcess);

  // --------------------------------------------------------------

  HANDLE hThread = CreateThread(NULL, 0, [](LPVOID) -> DWORD { return 0; }, NULL, 0, NULL);
  if (hThread == NULL) {
    std::cerr << "Failed to create thread!" << std::endl;
    return 1;
  }

  char* result6 = RetrieveKernelObjAccessMask(hThread);
  std::cout << "THREAD:\n" << result6 << std::endl;
  delete[] result6;
  CloseHandle(hThread);

  // --------------------------------------------------------------


  FreeLibrary(hModule);
  return 0;
}