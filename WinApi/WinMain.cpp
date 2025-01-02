#include "Definitions.h"

HWND FilePath;
HWND AccessInfo;

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrevInst, LPSTR args, int ncmdshow) {
	WNDCLASS MainClass = NewWindowClass((HBRUSH)COLOR_WINDOW, LoadCursor(NULL, IDC_ARROW), LoadIcon(NULL, IDI_APPLICATION), L"MainClass", hInst, MainProcedure);

	if (!RegisterClassW(&MainClass)) return -1;

	CreateWindow(L"MainClass", L"Systems Programming - Course Project", WS_OVERLAPPEDWINDOW | WS_VISIBLE, WND_POS_X, WND_POS_Y, WND_WIDTH, WND_HEIGHT, NULL, NULL, NULL, NULL);

	MSG msg = { 0 };
	while (GetMessage(&msg, NULL, NULL, NULL)) {
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	return 0;
}


LRESULT CALLBACK MainProcedure(HWND hWnd, UINT msg, WPARAM wp, LPARAM lp) {
	switch (msg)
	{
	case WM_CREATE:
		AddMainMenu(hWnd);
		AddFilepickerInterface(hWnd, FilePath, AccessInfo);

		break;
	case WM_COMMAND:
		switch (wp) {
		case ID_ROOT_MENU_ITEM_AUTHOR:
			MessageBoxA(hWnd, "ITINF-22-2 Student.\nYevhenii Dolhyi", "About Author", MB_OK);
			break;
		case ID_ROOT_MENU_ITEM_PROJECT:
			MessageBoxA(hWnd, "ITINF-22-2 Student`s Course Project.\nSubject: Systems Programing\nEnvironment: C++/WinApi", "About Project", MB_OK);
			break;
		case ID_PICKFILE_BUTTON:
			OPENFILENAME ofn;
			wchar_t szFile[260];

			ZeroMemory(&ofn, sizeof(ofn));
			ofn.lStructSize = sizeof(ofn);
			ofn.hwndOwner = hWnd;
			ofn.lpstrFile = szFile;
			ofn.lpstrFile[0] = '\0';
			ofn.nMaxFile = sizeof(szFile);
			ofn.nFilterIndex = 1;
			ofn.lpstrFileTitle = NULL;
			ofn.nMaxFileTitle = 0;
			ofn.lpstrInitialDir = NULL;
			ofn.lpstrTitle = L"Select a File";
			ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

			if (GetOpenFileName(&ofn) == TRUE) {
				SetWindowText(FilePath, szFile);
				RetrieveFileAccessMask(szFile, hWnd, AccessInfo);
			}
			else {
				MessageBox(hWnd, L"No file selected", L"Error", MB_OK);
			}

			break;
		case ID_ROOT_MENU_ITEM_EXIT:
			CloseApp();
			break;
		default:
			break;
		}
		break;
	case WM_DESTROY:
		CloseApp();
		break;
	default:
		return DefWindowProc(hWnd, msg, wp, lp);
	}
}


WNDCLASS NewWindowClass(HBRUSH BGColor, HCURSOR Cursor, HICON Icon, LPCWSTR Name, HINSTANCE hInst, WNDPROC Procedure) {
	WNDCLASS NWC = { 0 };

	NWC.hCursor = Cursor;
	NWC.hIcon = Icon;
	NWC.lpszClassName = Name;
	NWC.hbrBackground = BGColor;
	NWC.lpfnWndProc = Procedure;

	return NWC;
}

void CloseApp() {
	PostQuitMessage(0);
}