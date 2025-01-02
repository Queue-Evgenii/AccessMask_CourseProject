#include "Definitions.h"

void AddMainMenu(HWND hWnd) {
	HMENU RootMenu = CreateMenu();
	HMENU SubMenuFile = CreateMenu();
	HMENU SubMenuAbout = CreateMenu();

	AppendMenuW(SubMenuFile, MF_STRING, ID_ROOT_MENU_ITEM_EXIT, L"Exit");
	AppendMenuW(RootMenu, MF_POPUP, (UINT_PTR)SubMenuFile, L"File");


	AppendMenuW(SubMenuAbout, MF_STRING, ID_ROOT_MENU_ITEM_AUTHOR, L"Author");
	AppendMenuW(SubMenuAbout, MF_STRING, ID_ROOT_MENU_ITEM_PROJECT, L"Project");
	AppendMenuW(RootMenu, MF_POPUP, (UINT_PTR)SubMenuAbout, L"About");

	SetMenu(hWnd, RootMenu);
}

void AddFilepickerInterface(HWND hWnd, HWND& TextBox1, HWND& TextBox2) {
	unsigned short buttonStartPos = 16, buttonWidth = 128, defaultLineHeigth = 16, offset = 16, fontOffset = 4;
	TextBox1 = CreateWindowA(
		"static",
		"No picked file.",
		WS_VISIBLE | WS_CHILD | ES_LEFT | WS_DISABLED,
		buttonStartPos + buttonWidth + offset, buttonStartPos,
		WND_WIDTH - (buttonWidth + offset + buttonStartPos), defaultLineHeigth,
		hWnd,
		NULL,
		NULL,
		NULL
	);
	TextBox2 = CreateWindowA(
		"edit",
		"No info about access to picked file.",
		WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
		buttonStartPos, buttonStartPos + defaultLineHeigth + offset,
		WND_WIDTH - offset * 2, WND_HEIGHT - (defaultLineHeigth + fontOffset + buttonStartPos) * 3,
		hWnd,
		NULL,
		NULL,
		NULL
	);
	CreateWindowA("button", "Pick File", WS_VISIBLE | WS_CHILD, buttonStartPos, buttonStartPos, buttonWidth, defaultLineHeigth + fontOffset, hWnd, (HMENU)ID_PICKFILE_BUTTON, NULL, NULL);
}
