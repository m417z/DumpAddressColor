#include "stdafx.h"
#include "include/plugin.h"

#define DEF_NAME      L"DumpAddressColor"
#define DEF_VERSION   L"1.0"
#define DEF_COPYRIGHT L"Copyright (C) 2015 RaMMicHaeL"

static HINSTANCE hInst;

// Settings
static DWORD dwDrawColors[] = { DRAW_BREAK, DRAW_COND, DRAW_BDIS, DRAW_EIP }; // colors: module code, module data, some memory, window of the debuggee
static BOOL bOnlyAlligned = TRUE;

static BOOL bColorizeEnabled = FALSE;

static int __cdecl MainMenuFunc(t_table *pt, wchar_t *name, ulong index, int mode);
static int ColorizeDumpDataRow(t_dump *pd, wchar_t *s, uchar *mask, int n, int *select, ulong addr);

BOOL APIENTRY DllMain(HANDLE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	switch(ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hModule);
		hInst = (HINSTANCE)hModule;
		break;

	case DLL_PROCESS_DETACH:
		break;
	}

	return TRUE;
}

// ODBG2_Pluginquery() is a "must" for valid OllyDbg plugin. It must check
// whether given OllyDbg version is correctly supported, and return 0 if not.
// Then it should fill plugin name and plugin version (as UNICODE strings) and
// return version of expected plugin interface. If OllyDbg decides that this
// plugin is not compatible, it will be unloaded. Plugin name identifies it
// in the Plugins menu. This name is max. 31 alphanumerical UNICODE characters
// or spaces + terminating L'\0' long. To keep life easy for users, name must
// be descriptive and correlate with the name of DLL. Parameter features is
// reserved for the future. I plan that features[0] will contain the number
// of additional entries in features[]. Attention, this function should not
// call any API functions: they may be incompatible with the version of plugin!
extc int __cdecl ODBG2_Pluginquery(int ollydbgversion, ulong *features,
	wchar_t pluginname[SHORTNAME], wchar_t pluginversion[SHORTNAME])
{
	// Check whether OllyDbg has compatible version. This plugin uses only the
	// most basic functions, so this check is done pro forma, just to remind of
	// this option.
	if(ollydbgversion < 201)
		return 0;

	// Report name and version to OllyDbg.
	lstrcpy(pluginname, DEF_NAME); // Name of plugin
	lstrcpy(pluginversion, DEF_VERSION); // Version of plugin

	return PLUGIN_VERSION; // Expected API version
}

// Optional entry, called immediately after ODBG2_Pluginquery(). Plugin should
// make one-time initializations and allocate resources. On error, it must
// clean up and return -1. On success, it must return 0.
extc int __cdecl ODBG2_Plugininit(void)
{
	DWORD dwSetting;

	if(Getfromini(NULL, DEF_NAME, L"color_module_code", L"%u", &dwSetting))
		dwDrawColors[0] = (dwSetting & DRAW_COLOR);
	else
		Writetoini(NULL, DEF_NAME, L"color_module_code", L"%u", dwDrawColors[0]);

	if(Getfromini(NULL, DEF_NAME, L"color_module_data", L"%u", &dwSetting))
		dwDrawColors[1] = (dwSetting & DRAW_COLOR);
	else
		Writetoini(NULL, DEF_NAME, L"color_module_data", L"%u", dwDrawColors[1]);

	if(Getfromini(NULL, DEF_NAME, L"color_some_memory", L"%u", &dwSetting))
		dwDrawColors[2] = (dwSetting & DRAW_COLOR);
	else
		Writetoini(NULL, DEF_NAME, L"color_some_memory", L"%u", dwDrawColors[2]);

	if(Getfromini(NULL, DEF_NAME, L"only_alligned", L"%u", &dwSetting))
		bOnlyAlligned = (dwSetting != 0);
	else
		Writetoini(NULL, DEF_NAME, L"only_alligned", L"%u", bOnlyAlligned);

	return 0;
}

// Adds items either to main OllyDbg menu (type=PWM_MAIN) or to popup menu in
// one of the standard OllyDbg windows, like PWM_DISASM or PWM_MEMORY. When
// type matches, plugin should return address of menu. When there is no menu of
// given type, it must return NULL. If menu includes single item, it will
// appear directly in menu, otherwise OllyDbg will create a submenu with the
// name of plugin. Therefore, if there is only one item, make its name as
// descriptive as possible.
extc t_menu * __cdecl ODBG2_Pluginmenu(wchar_t *type)
{
	static t_menu mainmenu[] = {
			{ L"&Colorize dump window",
			NULL,
			KK_DIRECT | KK_CTRL | 'H', MainMenuFunc, NULL, 0 },
			{ L"&Only aligned addresses",
			NULL,
			K_NONE, MainMenuFunc, NULL, 1 },
			{ L"|&About " DEF_NAME,
			NULL,
			K_NONE, MainMenuFunc, NULL, 2 },
			{ NULL, NULL, K_NONE, NULL, NULL, 0 }
	};

	if(lstrcmp(type, PWM_MAIN) == 0)
		return mainmenu;

	return NULL;
}

// Dump windows display contents of memory or file as bytes, characters,
// integers, floats or disassembled commands. Plugins have the option to modify
// the contents of the dump windows. If ODBG2_Plugindump() is present and some
// dump window is being redrawn, this function is called first with column=
// DF_FILLCACHE, addr set to the address of the first visible element in the
// dump window and n to the estimated total size of the data displayed in the
// window (n may be significantly higher than real data size for disassembly).
// If plugin returns 0, there are no elements that will be modified by plugin
// and it will receive no other calls. If necessary, plugin may cache some data
// necessary later. OllyDbg guarantees that there are no calls to
// ODBG2_Plugindump() from other dump windows till the final call with
// DF_FREECACHE.
// When OllyDbg draws table, there is one call for each table cell (line/column
// pair). Parameters s (UNICODE), mask (DRAW_xxx) and select (extended DRAW_xxx
// set) contain description of the generated contents of length n. Plugin may
// modify it and return corrected length, or just return the original length.
// When table is completed, ODBG2_Plugindump() receives final call with
// column=DF_FREECACHE. This is the time to free resources allocated on
// DF_FILLCACHE. Returned value is ignored.
// Use this feature only if absolutely necessary, because it may strongly
// impair the responsiveness of the OllyDbg. Always make it switchable with
// default set to OFF!
extc int __cdecl ODBG2_Plugindump(t_dump *pd, wchar_t *s, uchar *mask, int n, int *select, ulong addr, int column)
{
	if(column == DF_FILLCACHE)
	{
		if(!bColorizeEnabled)
			return 0; // Not enabled

		// Check whether it's Dump pane of the CPU window.
		if(pd == NULL || (pd->menutype & DMT_CPUMASK) != DMT_CPUDUMP)
			return 0; // Not the Dump pane

		// Just for the sake, assure that it is not a file dump.
		if(pd->filecopy != NULL)
			return 0; // Invalid dump type

		switch(pd->dumptype & DU_TYPEMASK)
		{
		case DU_HEXTEXT:
		case DU_HEXUNI:
		case 0x000E0000: // UTF-8
			// OK.
			break;

		case DU_INT:
		case DU_UINT:
		case DU_IHEX:
		case DU_ADDR:
		case DU_ADRASC:
		case DU_ADRUNI:
			if((pd->dumptype & DU_SIZEMASK) != sizeof(DWORD))
				return 0;

			// OK.
			break;

		default:
			// We don't handle this dump type.
			return 0;
		}

		return 1;
	}
	else if(column == 1)
	{
		n = ColorizeDumpDataRow(pd, s, mask, n, select, addr);
	}
	else if(column == DF_FREECACHE)
	{
		// We have allocated no resources, so we have nothing to do here.
	}

	return n;
}

static int ColorizeDumpDataRow(t_dump *pd, wchar_t *s, uchar *mask, int n, int *select, ulong addr)
{
	if(addr < pd->base || addr >= pd->base + pd->size)
		return n;

	DWORD dwItemSize = (pd->dumptype & DU_SIZEMASK);
	DWORD dwItemsPerLine = (pd->dumptype & DU_COUNTMASK) >> 8;
	DWORD dwBytesPerLine = dwItemSize * dwItemsPerLine;
	if(dwBytesPerLine > 256)
		return n;

	DWORD dwBytesAvailable = dwBytesPerLine;
	if(dwBytesAvailable > pd->base + pd->size - addr)
		dwBytesAvailable = pd->base + pd->size - addr;

	BYTE bBuffer[256];
	DWORD dwReadMemory = Readmemory(bBuffer, addr, dwBytesAvailable, MM_SILENT | MM_PARTIAL);
	if(dwBytesAvailable > dwReadMemory)
		dwBytesAvailable = dwReadMemory;

	if(dwBytesAvailable < sizeof(DWORD))
		return n;

	if((*select & DRAW_MASK) == 0)
	{
		FillMemory(mask, DRAW_NORMAL, n);
		*select |= DRAW_MASK;
	}
	else
	{
		// Remove all colors.
		for(int i = 0; i < n; i++)
			mask[i] &= ~DRAW_COLOR;
	}

	for(DWORD dwIter = 0; dwIter < dwBytesAvailable - sizeof(DWORD) + 1; dwIter += dwItemSize)
	{
		if(bOnlyAlligned && ((addr + dwIter) % sizeof(DWORD)) != 0)
			continue;

		DWORD dwAddress = *(DWORD *)(bBuffer + dwIter);
		if(!dwAddress)
			continue;

		DWORD dwDraw = DRAW_NORMAL;

		t_module *pModule = Findmodule(dwAddress);
		if(pModule && !(pModule->type & MOD_HIDDEN))
		{
			if(dwAddress >= pModule->codebase && dwAddress < pModule->codebase + pModule->codesize)
				dwDraw = dwDrawColors[0];
			else
				dwDraw = dwDrawColors[1];
		}

		if(dwDraw == DRAW_NORMAL)
		{
			t_memory *pMemory = Findmemory(dwAddress);
			if(pMemory)
				dwDraw = dwDrawColors[2];
		}

		if(dwDraw == DRAW_NORMAL)
		{
			HWND hWnd = (HWND)dwAddress;
			DWORD dwProcessId;
			if(IsWindow(hWnd) && GetWindowThreadProcessId(hWnd, &dwProcessId) && dwProcessId == processid)
			{
				dwDraw = dwDrawColors[3];
			}
		}

		if(dwDraw == DRAW_NORMAL)
			continue;

		DWORD dwItemPos = (dwIter / dwItemSize) * pd->itemwidth;
		switch(pd->dumptype & DU_TYPEMASK)
		{
		case DU_ADDR:
		case DU_ADRASC:
		case DU_ADRUNI:
			dwItemPos++; // OllyDbg starts counting from index 1 for addresses
			break;
		}

		// Remove color from the space just before the item.
		DWORD dwSkipCount = 0;
		if(s[dwItemPos] == L' ')
		{
			mask[dwItemPos] &= ~DRAW_COLOR;
			dwSkipCount = 1;
		}
		else if(dwItemPos > 0 && s[dwItemPos - 1] == L' ')
		{
			mask[dwItemPos - 1] &= ~DRAW_COLOR;
		}

		int nItemsToHighlight = sizeof(DWORD) / dwItemSize;
		for(DWORD i = dwSkipCount; i < pd->itemwidth * nItemsToHighlight; i++)
		{
			mask[dwItemPos + i] &= ~DRAW_COLOR;
			mask[dwItemPos + i] |= dwDraw;
		}
	}

	return n;
}

/*
// OllyDbg calls this optional function when user wants to terminate OllyDbg.
// All MDI windows created by plugins still exist. Function must return 0 if
// it is safe to terminate. Any non-zero return will stop closing sequence. Do
// not misuse this possibility! Always inform user about the reasons why
// termination is not good and ask for his decision! Attention, don't make any
// unrecoverable actions for the case that some other plugin will decide that
// OllyDbg should continue running.
extc int __cdecl ODBG2_Pluginclose(void)
{
	return 0;
}
*/

/*
// OllyDbg calls this optional function once on exit. At this moment, all MDI
// windows created by plugin are already destroyed (and received WM_DESTROY
// messages). Function must free all internally allocated resources, like
// window classes, files, memory etc.
extc void __cdecl ODBG2_Plugindestroy(void)
{
}
*/

static int __cdecl MainMenuFunc(t_table *pt, wchar_t *name, ulong index, int mode)
{
	switch(mode)
	{
	case MENU_VERIFY:
		switch(index)
		{
		case 0:
			if(bColorizeEnabled)
				return MENU_CHECKED;
			break;

		case 1:
			if(bOnlyAlligned)
				return MENU_CHECKED;
			break;
		}

		return MENU_NORMAL; // Always available

	case MENU_EXECUTE:
		switch(index)
		{
		case 0:
			bColorizeEnabled = !bColorizeEnabled;
			return MENU_REDRAW;

		case 1:
			bOnlyAlligned = !bOnlyAlligned;
			Writetoini(NULL, DEF_NAME, L"only_alligned", L"%u", bOnlyAlligned);
			if(bColorizeEnabled)
				return MENU_REDRAW;
			break;

		case 2:
			// Debuggee should continue execution while message box is displayed.
			Resumeallthreads();

			// Menu item "About", displays plugin info.
			MessageBox(
				hwollymain, 
				DEF_NAME L" plugin v" DEF_VERSION L"\n"
				DEF_COPYRIGHT,
				DEF_NAME,
				MB_ICONASTERISK
			);

			// Suspendallthreads() and Resumeallthreads() must be paired, even if they
			// are called in inverse order!
			Suspendallthreads();
			break;
		}

		return MENU_NOREDRAW;
	}

	return MENU_ABSENT;
}
