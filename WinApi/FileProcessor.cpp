#include "Definitions.h"
#include <locale>
#include <codecvt>

typedef char* (*RetrieveAccessMaskStringFunc)(const char*);

void RetrieveFileAccessMask(wchar_t* filePath, HWND hWnd, HWND TextBox) {
  HMODULE hModule = LoadLibrary(L"AccessMaskProcessor.dll");
  if (hModule == NULL) {
    MessageBox(hWnd, L"Failed to load DLL!", L"Error", MB_OK);
    return;
  }

  RetrieveAccessMaskStringFunc RetrieveAccessMaskString = (RetrieveAccessMaskStringFunc)GetProcAddress(hModule, "RetrieveFileAccessInfo");
  if (RetrieveAccessMaskString == NULL) {
    MessageBox(hWnd, L"Failed to find function!", L"Error", MB_OK);
    FreeLibrary(hModule);
    return;
  }

  std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
  std::string utf8_str = converter.to_bytes(filePath);
  const char* char_filePath = utf8_str.c_str();

  char* result = RetrieveAccessMaskString(char_filePath);
  SetWindowTextA(TextBox, result);
  delete[] result;
  FreeLibrary(hModule);
}