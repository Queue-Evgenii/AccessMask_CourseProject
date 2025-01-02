#pragma once
#include "Definitions.h"

LRESULT CALLBACK MainProcedure(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp);
WNDCLASS NewWindowClass(HBRUSH BGColor, HCURSOR Cursor, HICON Icon, LPCWSTR Name, HINSTANCE hInst, WNDPROC Procedure);

void AddMainMenu(HWND hWnd);
void AddFilepickerInterface(HWND, HWND&, HWND&);

void RetrieveFileAccessMask(wchar_t*, HWND, HWND);

void CloseApp();