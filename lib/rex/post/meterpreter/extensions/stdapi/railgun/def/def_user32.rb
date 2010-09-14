module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_user32

	def self.add_imports(railgun)
		
		railgun.add_dll('user32')

		railgun.add_function( 'user32', 'ActivateKeyboardLayout', 'DWORD',[
			["DWORD","hkl","in"],
			["DWORD","Flags","in"],
			])

		railgun.add_function( 'user32', 'AdjustWindowRect', 'BOOL',[
			["PBLOB","lpRect","inout"],
			["DWORD","dwStyle","in"],
			["BOOL","bMenu","in"],
			])

		railgun.add_function( 'user32', 'AdjustWindowRectEx', 'BOOL',[
			["PBLOB","lpRect","inout"],
			["DWORD","dwStyle","in"],
			["BOOL","bMenu","in"],
			["DWORD","dwExStyle","in"],
			])

		railgun.add_function( 'user32', 'AllowSetForegroundWindow', 'BOOL',[
			["DWORD","dwProcessId","in"],
			])

		railgun.add_function( 'user32', 'AnimateWindow', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","dwTime","in"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'user32', 'AnyPopup', 'BOOL',[
			])

		railgun.add_function( 'user32', 'AppendMenuA', 'BOOL',[
			["DWORD","hMenu","in"],
			["DWORD","uFlags","in"],
			["DWORD","uIDNewItem","in"],
			["PCHAR","lpNewItem","in"],
			])

		railgun.add_function( 'user32', 'AppendMenuW', 'BOOL',[
			["DWORD","hMenu","in"],
			["DWORD","uFlags","in"],
			["DWORD","uIDNewItem","in"],
			["PWCHAR","lpNewItem","in"],
			])

		railgun.add_function( 'user32', 'ArrangeIconicWindows', 'DWORD',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'AttachThreadInput', 'BOOL',[
			["DWORD","idAttach","in"],
			["DWORD","idAttachTo","in"],
			["BOOL","fAttach","in"],
			])

		railgun.add_function( 'user32', 'BeginDeferWindowPos', 'DWORD',[
			["DWORD","nNumWindows","in"],
			])

		railgun.add_function( 'user32', 'BeginPaint', 'DWORD',[
			["DWORD","hWnd","in"],
			["PBLOB","lpPaint","out"],
			])

		railgun.add_function( 'user32', 'BringWindowToTop', 'BOOL',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'BroadcastSystemMessage', 'DWORD',[
			["DWORD","flags","in"],
			["PDWORD","lpInfo","inout"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'BroadcastSystemMessageA', 'DWORD',[
			["DWORD","flags","in"],
			["PDWORD","lpInfo","inout"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'BroadcastSystemMessageExA', 'DWORD',[
			["DWORD","flags","in"],
			["PDWORD","lpInfo","inout"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			["PBLOB","pbsmInfo","out"],
			])

		railgun.add_function( 'user32', 'BroadcastSystemMessageExW', 'DWORD',[
			["DWORD","flags","in"],
			["PDWORD","lpInfo","inout"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			["PBLOB","pbsmInfo","out"],
			])

		railgun.add_function( 'user32', 'BroadcastSystemMessageW', 'DWORD',[
			["DWORD","flags","in"],
			["PDWORD","lpInfo","inout"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'CallMsgFilterA', 'BOOL',[
			["PBLOB","lpMsg","in"],
			["DWORD","nCode","in"],
			])

		railgun.add_function( 'user32', 'CallMsgFilterW', 'BOOL',[
			["PBLOB","lpMsg","in"],
			["DWORD","nCode","in"],
			])

		railgun.add_function( 'user32', 'CallNextHookEx', 'DWORD',[
			["DWORD","hhk","in"],
			["DWORD","nCode","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'CallWindowProcA', 'DWORD',[
			["PBLOB","lpPrevWndFunc","in"],
			["DWORD","hWnd","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'CallWindowProcW', 'DWORD',[
			["PBLOB","lpPrevWndFunc","in"],
			["DWORD","hWnd","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'CascadeWindows', 'WORD',[
			["DWORD","hwndParent","in"],
			["DWORD","wHow","in"],
			["PBLOB","lpRect","in"],
			["DWORD","cKids","in"],
			["PDWORD","lpKids","in"],
			])

		railgun.add_function( 'user32', 'ChangeClipboardChain', 'BOOL',[
			["DWORD","hWndRemove","in"],
			["DWORD","hWndNewNext","in"],
			])

		railgun.add_function( 'user32', 'ChangeDisplaySettingsA', 'DWORD',[
			["PBLOB","lpDevMode","in"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'user32', 'ChangeDisplaySettingsExA', 'DWORD',[
			["PCHAR","lpszDeviceName","in"],
			["PBLOB","lpDevMode","in"],
			["DWORD","hwnd","inout"],
			["DWORD","dwflags","in"],
			["PBLOB","lParam","in"],
			])

		railgun.add_function( 'user32', 'ChangeDisplaySettingsExW', 'DWORD',[
			["PWCHAR","lpszDeviceName","in"],
			["PBLOB","lpDevMode","in"],
			["DWORD","hwnd","inout"],
			["DWORD","dwflags","in"],
			["PBLOB","lParam","in"],
			])

		railgun.add_function( 'user32', 'ChangeDisplaySettingsW', 'DWORD',[
			["PBLOB","lpDevMode","in"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'user32', 'ChangeMenuA', 'BOOL',[
			["DWORD","hMenu","in"],
			["DWORD","cmd","in"],
			["PCHAR","lpszNewItem","in"],
			["DWORD","cmdInsert","in"],
			["DWORD","flags","in"],
			])

		railgun.add_function( 'user32', 'ChangeMenuW', 'BOOL',[
			["DWORD","hMenu","in"],
			["DWORD","cmd","in"],
			["PWCHAR","lpszNewItem","in"],
			["DWORD","cmdInsert","in"],
			["DWORD","flags","in"],
			])

		railgun.add_function( 'user32', 'CharLowerBuffA', 'DWORD',[
			["PCHAR","lpsz","in"],
			["DWORD","cchLength","in"],
			])

		railgun.add_function( 'user32', 'CharLowerBuffW', 'DWORD',[
			["PWCHAR","lpsz","in"],
			["DWORD","cchLength","in"],
			])

		railgun.add_function( 'user32', 'CharToOemA', 'BOOL',[
			["PCHAR","lpszSrc","in"],
			["PCHAR","lpszDst","out"],
			])

		railgun.add_function( 'user32', 'CharToOemBuffA', 'BOOL',[
			["PCHAR","lpszSrc","in"],
			["PCHAR","lpszDst","out"],
			["DWORD","cchDstLength","in"],
			])

		railgun.add_function( 'user32', 'CharToOemBuffW', 'BOOL',[
			["PWCHAR","lpszSrc","in"],
			["PCHAR","lpszDst","out"],
			["DWORD","cchDstLength","in"],
			])

		railgun.add_function( 'user32', 'CharToOemW', 'BOOL',[
			["PWCHAR","lpszSrc","in"],
			["PCHAR","lpszDst","out"],
			])

		railgun.add_function( 'user32', 'CharUpperBuffA', 'DWORD',[
			["PCHAR","lpsz","in"],
			["DWORD","cchLength","in"],
			])

		railgun.add_function( 'user32', 'CharUpperBuffW', 'DWORD',[
			["PWCHAR","lpsz","in"],
			["DWORD","cchLength","in"],
			])

		railgun.add_function( 'user32', 'CheckDlgButton', 'BOOL',[
			["DWORD","hDlg","in"],
			["DWORD","nIDButton","in"],
			["DWORD","uCheck","in"],
			])

		railgun.add_function( 'user32', 'CheckMenuItem', 'DWORD',[
			["DWORD","hMenu","in"],
			["DWORD","uIDCheckItem","in"],
			["DWORD","uCheck","in"],
			])

		railgun.add_function( 'user32', 'CheckMenuRadioItem', 'BOOL',[
			["DWORD","hmenu","in"],
			["DWORD","first","in"],
			["DWORD","last","in"],
			["DWORD","check","in"],
			["DWORD","flags","in"],
			])

		railgun.add_function( 'user32', 'CheckRadioButton', 'BOOL',[
			["DWORD","hDlg","in"],
			["DWORD","nIDFirstButton","in"],
			["DWORD","nIDLastButton","in"],
			["DWORD","nIDCheckButton","in"],
			])

		railgun.add_function( 'user32', 'ChildWindowFromPoint', 'DWORD',[
			["DWORD","hWndParent","in"],
			["PBLOB","Point","in"],
			])

		railgun.add_function( 'user32', 'ChildWindowFromPointEx', 'DWORD',[
			["DWORD","hwnd","in"],
			["PBLOB","pt","in"],
			["DWORD","flags","in"],
			])

		railgun.add_function( 'user32', 'ClientToScreen', 'BOOL',[
			["DWORD","hWnd","in"],
			["PBLOB","lpPoint","inout"],
			])

		railgun.add_function( 'user32', 'ClipCursor', 'BOOL',[
			["PBLOB","lpRect","in"],
			])

		railgun.add_function( 'user32', 'CloseClipboard', 'BOOL',[
			])

		railgun.add_function( 'user32', 'CloseDesktop', 'BOOL',[
			["DWORD","hDesktop","in"],
			])

		railgun.add_function( 'user32', 'CloseWindow', 'BOOL',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'CloseWindowStation', 'BOOL',[
			["DWORD","hWinSta","in"],
			])

		railgun.add_function( 'user32', 'CopyAcceleratorTableA', 'DWORD',[
			["DWORD","hAccelSrc","in"],
			["PBLOB","lpAccelDst","out"],
			["DWORD","cAccelEntries","in"],
			])

		railgun.add_function( 'user32', 'CopyAcceleratorTableW', 'DWORD',[
			["DWORD","hAccelSrc","in"],
			["PBLOB","lpAccelDst","out"],
			["DWORD","cAccelEntries","in"],
			])

		railgun.add_function( 'user32', 'CopyIcon', 'DWORD',[
			["DWORD","hIcon","in"],
			])

		railgun.add_function( 'user32', 'CopyImage', 'DWORD',[
			["DWORD","h","in"],
			["DWORD","type","in"],
			["DWORD","cx","in"],
			["DWORD","cy","in"],
			["DWORD","flags","in"],
			])

		railgun.add_function( 'user32', 'CopyRect', 'BOOL',[
			["PBLOB","lprcDst","out"],
			["PBLOB","lprcSrc","in"],
			])

		railgun.add_function( 'user32', 'CountClipboardFormats', 'DWORD',[
			])

		railgun.add_function( 'user32', 'CreateAcceleratorTableA', 'DWORD',[
			["PBLOB","paccel","in"],
			["DWORD","cAccel","in"],
			])

		railgun.add_function( 'user32', 'CreateAcceleratorTableW', 'DWORD',[
			["PBLOB","paccel","in"],
			["DWORD","cAccel","in"],
			])

		railgun.add_function( 'user32', 'CreateCaret', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","hBitmap","in"],
			["DWORD","nWidth","in"],
			["DWORD","nHeight","in"],
			])

		railgun.add_function( 'user32', 'CreateCursor', 'DWORD',[
			["DWORD","hInst","in"],
			["DWORD","xHotSpot","in"],
			["DWORD","yHotSpot","in"],
			["DWORD","nWidth","in"],
			["DWORD","nHeight","in"],
			])

		railgun.add_function( 'user32', 'CreateDesktopA', 'DWORD',[
			["PCHAR","lpszDesktop","in"],
			["PCHAR","lpszDevice","inout"],
			["PBLOB","pDevmode","inout"],
			["DWORD","dwFlags","in"],
			["DWORD","dwDesiredAccess","in"],
			["PBLOB","lpsa","in"],
			])

		railgun.add_function( 'user32', 'CreateDesktopW', 'DWORD',[
			["PWCHAR","lpszDesktop","in"],
			["PWCHAR","lpszDevice","inout"],
			["PBLOB","pDevmode","inout"],
			["DWORD","dwFlags","in"],
			["DWORD","dwDesiredAccess","in"],
			["PBLOB","lpsa","in"],
			])

		railgun.add_function( 'user32', 'CreateDialogIndirectParamA', 'DWORD',[
			["DWORD","hInstance","in"],
			["PBLOB","lpTemplate","in"],
			["DWORD","hWndParent","in"],
			["PBLOB","lpDialogFunc","in"],
			["DWORD","dwInitParam","in"],
			])

		railgun.add_function( 'user32', 'CreateDialogIndirectParamW', 'DWORD',[
			["DWORD","hInstance","in"],
			["PBLOB","lpTemplate","in"],
			["DWORD","hWndParent","in"],
			["PBLOB","lpDialogFunc","in"],
			["DWORD","dwInitParam","in"],
			])

		railgun.add_function( 'user32', 'CreateDialogParamA', 'DWORD',[
			["DWORD","hInstance","in"],
			["PCHAR","lpTemplateName","in"],
			["DWORD","hWndParent","in"],
			["PBLOB","lpDialogFunc","in"],
			["DWORD","dwInitParam","in"],
			])

		railgun.add_function( 'user32', 'CreateDialogParamW', 'DWORD',[
			["DWORD","hInstance","in"],
			["PWCHAR","lpTemplateName","in"],
			["DWORD","hWndParent","in"],
			["PBLOB","lpDialogFunc","in"],
			["DWORD","dwInitParam","in"],
			])

		railgun.add_function( 'user32', 'CreateIcon', 'DWORD',[
			["DWORD","hInstance","in"],
			["DWORD","nWidth","in"],
			["DWORD","nHeight","in"],
			["BYTE","cPlanes","in"],
			["BYTE","cBitsPixel","in"],
			["PBLOB","lpbANDbits","in"],
			["PBLOB","lpbXORbits","in"],
			])

		railgun.add_function( 'user32', 'CreateIconFromResource', 'DWORD',[
			["PBLOB","presbits","in"],
			["DWORD","dwResSize","in"],
			["BOOL","fIcon","in"],
			["DWORD","dwVer","in"],
			])

		railgun.add_function( 'user32', 'CreateIconFromResourceEx', 'DWORD',[
			["PBLOB","presbits","in"],
			["DWORD","dwResSize","in"],
			["BOOL","fIcon","in"],
			["DWORD","dwVer","in"],
			["DWORD","cxDesired","in"],
			["DWORD","cyDesired","in"],
			["DWORD","Flags","in"],
			])

		railgun.add_function( 'user32', 'CreateIconIndirect', 'DWORD',[
			["PBLOB","piconinfo","in"],
			])

		railgun.add_function( 'user32', 'CreateMDIWindowA', 'DWORD',[
			["PCHAR","lpClassName","in"],
			["PCHAR","lpWindowName","in"],
			["DWORD","dwStyle","in"],
			["DWORD","X","in"],
			["DWORD","Y","in"],
			["DWORD","nWidth","in"],
			["DWORD","nHeight","in"],
			["DWORD","hWndParent","in"],
			["DWORD","hInstance","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'CreateMDIWindowW', 'DWORD',[
			["PWCHAR","lpClassName","in"],
			["PWCHAR","lpWindowName","in"],
			["DWORD","dwStyle","in"],
			["DWORD","X","in"],
			["DWORD","Y","in"],
			["DWORD","nWidth","in"],
			["DWORD","nHeight","in"],
			["DWORD","hWndParent","in"],
			["DWORD","hInstance","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'CreateMenu', 'DWORD',[
			])

		railgun.add_function( 'user32', 'CreatePopupMenu', 'DWORD',[
			])

		railgun.add_function( 'user32', 'CreateWindowExA', 'DWORD',[
			["DWORD","dwExStyle","in"],
			["PCHAR","lpClassName","in"],
			["PCHAR","lpWindowName","in"],
			["DWORD","dwStyle","in"],
			["DWORD","X","in"],
			["DWORD","Y","in"],
			["DWORD","nWidth","in"],
			["DWORD","nHeight","in"],
			["DWORD","hWndParent","in"],
			["DWORD","hMenu","in"],
			["DWORD","hInstance","in"],
			["PBLOB","lpParam","in"],
			])

		railgun.add_function( 'user32', 'CreateWindowExW', 'DWORD',[
			["DWORD","dwExStyle","in"],
			["PWCHAR","lpClassName","in"],
			["PWCHAR","lpWindowName","in"],
			["DWORD","dwStyle","in"],
			["DWORD","X","in"],
			["DWORD","Y","in"],
			["DWORD","nWidth","in"],
			["DWORD","nHeight","in"],
			["DWORD","hWndParent","in"],
			["DWORD","hMenu","in"],
			["DWORD","hInstance","in"],
			["PBLOB","lpParam","in"],
			])

		railgun.add_function( 'user32', 'CreateWindowStationA', 'DWORD',[
			["PCHAR","lpwinsta","in"],
			["DWORD","dwFlags","in"],
			["DWORD","dwDesiredAccess","in"],
			["PBLOB","lpsa","in"],
			])

		railgun.add_function( 'user32', 'CreateWindowStationW', 'DWORD',[
			["PWCHAR","lpwinsta","in"],
			["DWORD","dwFlags","in"],
			["DWORD","dwDesiredAccess","in"],
			["PBLOB","lpsa","in"],
			])

		railgun.add_function( 'user32', 'DefDlgProcA', 'DWORD',[
			["DWORD","hDlg","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'DefDlgProcW', 'DWORD',[
			["DWORD","hDlg","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'DefFrameProcA', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","hWndMDIClient","in"],
			["DWORD","uMsg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'DefFrameProcW', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","hWndMDIClient","in"],
			["DWORD","uMsg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'DefMDIChildProcA', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","uMsg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'DefMDIChildProcW', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","uMsg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'DefRawInputProc', 'DWORD',[
			["PBLOB","paRawInput","in"],
			["DWORD","nInput","in"],
			["DWORD","cbSizeHeader","in"],
			])

		railgun.add_function( 'user32', 'DefWindowProcA', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'DefWindowProcW', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'DeferWindowPos', 'DWORD',[
			["DWORD","hWinPosInfo","in"],
			["DWORD","hWnd","in"],
			["DWORD","hWndInsertAfter","in"],
			["DWORD","x","in"],
			["DWORD","y","in"],
			["DWORD","cx","in"],
			["DWORD","cy","in"],
			["DWORD","uFlags","in"],
			])

		railgun.add_function( 'user32', 'DeleteMenu', 'BOOL',[
			["DWORD","hMenu","in"],
			["DWORD","uPosition","in"],
			["DWORD","uFlags","in"],
			])

		railgun.add_function( 'user32', 'DeregisterShellHookWindow', 'BOOL',[
			["DWORD","hwnd","in"],
			])

		railgun.add_function( 'user32', 'DestroyAcceleratorTable', 'BOOL',[
			["DWORD","hAccel","in"],
			])

		railgun.add_function( 'user32', 'DestroyCaret', 'BOOL',[
			])

		railgun.add_function( 'user32', 'DestroyCursor', 'BOOL',[
			["DWORD","hCursor","in"],
			])

		railgun.add_function( 'user32', 'DestroyIcon', 'BOOL',[
			["DWORD","hIcon","in"],
			])

		railgun.add_function( 'user32', 'DestroyMenu', 'BOOL',[
			["DWORD","hMenu","in"],
			])

		railgun.add_function( 'user32', 'DestroyWindow', 'BOOL',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'DisableProcessWindowsGhosting', 'VOID',[
			])

		railgun.add_function( 'user32', 'DispatchMessageA', 'DWORD',[
			["PBLOB","lpMsg","in"],
			])

		railgun.add_function( 'user32', 'DispatchMessageW', 'DWORD',[
			["PBLOB","lpMsg","in"],
			])

		railgun.add_function( 'user32', 'DlgDirListA', 'DWORD',[
			["DWORD","hDlg","in"],
			["PCHAR","lpPathSpec","inout"],
			["DWORD","nIDListBox","in"],
			["DWORD","nIDStaticPath","in"],
			["DWORD","uFileType","in"],
			])

		railgun.add_function( 'user32', 'DlgDirListComboBoxA', 'DWORD',[
			["DWORD","hDlg","in"],
			["PCHAR","lpPathSpec","inout"],
			["DWORD","nIDComboBox","in"],
			["DWORD","nIDStaticPath","in"],
			["DWORD","uFiletype","in"],
			])

		railgun.add_function( 'user32', 'DlgDirListComboBoxW', 'DWORD',[
			["DWORD","hDlg","in"],
			["PWCHAR","lpPathSpec","inout"],
			["DWORD","nIDComboBox","in"],
			["DWORD","nIDStaticPath","in"],
			["DWORD","uFiletype","in"],
			])

		railgun.add_function( 'user32', 'DlgDirListW', 'DWORD',[
			["DWORD","hDlg","in"],
			["PWCHAR","lpPathSpec","inout"],
			["DWORD","nIDListBox","in"],
			["DWORD","nIDStaticPath","in"],
			["DWORD","uFileType","in"],
			])

		railgun.add_function( 'user32', 'DlgDirSelectComboBoxExA', 'BOOL',[
			["DWORD","hwndDlg","in"],
			["PCHAR","lpString","out"],
			["DWORD","cchOut","in"],
			["DWORD","idComboBox","in"],
			])

		railgun.add_function( 'user32', 'DlgDirSelectComboBoxExW', 'BOOL',[
			["DWORD","hwndDlg","in"],
			["PWCHAR","lpString","out"],
			["DWORD","cchOut","in"],
			["DWORD","idComboBox","in"],
			])

		railgun.add_function( 'user32', 'DlgDirSelectExA', 'BOOL',[
			["DWORD","hwndDlg","in"],
			["PCHAR","lpString","out"],
			["DWORD","chCount","in"],
			["DWORD","idListBox","in"],
			])

		railgun.add_function( 'user32', 'DlgDirSelectExW', 'BOOL',[
			["DWORD","hwndDlg","in"],
			["PWCHAR","lpString","out"],
			["DWORD","chCount","in"],
			["DWORD","idListBox","in"],
			])

		railgun.add_function( 'user32', 'DragDetect', 'BOOL',[
			["DWORD","hwnd","in"],
			["PBLOB","pt","in"],
			])

		railgun.add_function( 'user32', 'DragObject', 'DWORD',[
			["DWORD","hwndParent","in"],
			["DWORD","hwndFrom","in"],
			["DWORD","fmt","in"],
			["PDWORD","data","in"],
			["DWORD","hcur","in"],
			])

		railgun.add_function( 'user32', 'DrawAnimatedRects', 'BOOL',[
			["DWORD","hwnd","in"],
			["DWORD","idAni","in"],
			["PBLOB","lprcFrom","in"],
			["PBLOB","lprcTo","in"],
			])

		railgun.add_function( 'user32', 'DrawCaption', 'BOOL',[
			["DWORD","hwnd","in"],
			["DWORD","hdc","in"],
			["PBLOB","lprect","in"],
			["DWORD","flags","in"],
			])

		railgun.add_function( 'user32', 'DrawEdge', 'BOOL',[
			["DWORD","hdc","in"],
			["PBLOB","qrc","inout"],
			["DWORD","edge","in"],
			["DWORD","grfFlags","in"],
			])

		railgun.add_function( 'user32', 'DrawFocusRect', 'BOOL',[
			["DWORD","hDC","in"],
			["PBLOB","lprc","in"],
			])

		railgun.add_function( 'user32', 'DrawIcon', 'BOOL',[
			["DWORD","hDC","in"],
			["DWORD","X","in"],
			["DWORD","Y","in"],
			["DWORD","hIcon","in"],
			])

		railgun.add_function( 'user32', 'DrawIconEx', 'BOOL',[
			["DWORD","hdc","in"],
			["DWORD","xLeft","in"],
			["DWORD","yTop","in"],
			["DWORD","hIcon","in"],
			["DWORD","cxWidth","in"],
			["DWORD","cyWidth","in"],
			["DWORD","istepIfAniCur","in"],
			["DWORD","hbrFlickerFreeDraw","in"],
			["DWORD","diFlags","in"],
			])

		railgun.add_function( 'user32', 'DrawMenuBar', 'BOOL',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'DrawStateA', 'BOOL',[
			["DWORD","hdc","in"],
			["DWORD","hbrFore","in"],
			["PBLOB","qfnCallBack","in"],
			["DWORD","lData","in"],
			["WORD","wData","in"],
			["DWORD","x","in"],
			["DWORD","y","in"],
			["DWORD","cx","in"],
			["DWORD","cy","in"],
			["DWORD","uFlags","in"],
			])

		railgun.add_function( 'user32', 'DrawStateW', 'BOOL',[
			["DWORD","hdc","in"],
			["DWORD","hbrFore","in"],
			["PBLOB","qfnCallBack","in"],
			["DWORD","lData","in"],
			["WORD","wData","in"],
			["DWORD","x","in"],
			["DWORD","y","in"],
			["DWORD","cx","in"],
			["DWORD","cy","in"],
			["DWORD","uFlags","in"],
			])

		railgun.add_function( 'user32', 'DrawTextA', 'DWORD',[
			["DWORD","hdc","in"],
			["PCHAR","lpchText","in"],
			["DWORD","cchText","in"],
			["PBLOB","lprc","inout"],
			["DWORD","format","in"],
			])

		railgun.add_function( 'user32', 'DrawTextExA', 'DWORD',[
			["DWORD","hdc","in"],
			["PCHAR","lpchText","in"],
			["DWORD","cchText","in"],
			["PBLOB","lprc","inout"],
			["DWORD","format","in"],
			["PBLOB","lpdtp","in"],
			])

		railgun.add_function( 'user32', 'DrawTextExW', 'DWORD',[
			["DWORD","hdc","in"],
			["PWCHAR","lpchText","in"],
			["DWORD","cchText","in"],
			["PBLOB","lprc","inout"],
			["DWORD","format","in"],
			["PBLOB","lpdtp","in"],
			])

		railgun.add_function( 'user32', 'DrawTextW', 'DWORD',[
			["DWORD","hdc","in"],
			["PWCHAR","lpchText","in"],
			["DWORD","cchText","in"],
			["PBLOB","lprc","inout"],
			["DWORD","format","in"],
			])

		railgun.add_function( 'user32', 'EmptyClipboard', 'BOOL',[
			])

		railgun.add_function( 'user32', 'EnableMenuItem', 'BOOL',[
			["DWORD","hMenu","in"],
			["DWORD","uIDEnableItem","in"],
			["DWORD","uEnable","in"],
			])

		railgun.add_function( 'user32', 'EnableScrollBar', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","wSBflags","in"],
			["DWORD","wArrows","in"],
			])

		railgun.add_function( 'user32', 'EnableWindow', 'BOOL',[
			["DWORD","hWnd","in"],
			["BOOL","bEnable","in"],
			])

		railgun.add_function( 'user32', 'EndDeferWindowPos', 'BOOL',[
			["DWORD","hWinPosInfo","in"],
			])

		railgun.add_function( 'user32', 'EndDialog', 'BOOL',[
			["DWORD","hDlg","in"],
			["PDWORD","nResult","in"],
			])

		railgun.add_function( 'user32', 'EndMenu', 'BOOL',[
			])

		railgun.add_function( 'user32', 'EndPaint', 'BOOL',[
			["DWORD","hWnd","in"],
			["PBLOB","lpPaint","in"],
			])

		railgun.add_function( 'user32', 'EndTask', 'BOOL',[
			["DWORD","hWnd","in"],
			["BOOL","fShutDown","in"],
			["BOOL","fForce","in"],
			])

		railgun.add_function( 'user32', 'EnumChildWindows', 'BOOL',[
			["DWORD","hWndParent","in"],
			["PBLOB","lpEnumFunc","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'EnumClipboardFormats', 'DWORD',[
			["DWORD","format","in"],
			])

		railgun.add_function( 'user32', 'EnumDesktopWindows', 'BOOL',[
			["DWORD","hDesktop","in"],
			["PBLOB","lpfn","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'EnumDesktopsA', 'BOOL',[
			["DWORD","hwinsta","in"],
			["PBLOB","lpEnumFunc","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'EnumDesktopsW', 'BOOL',[
			["DWORD","hwinsta","in"],
			["PBLOB","lpEnumFunc","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'EnumDisplayDevicesA', 'BOOL',[
			["PCHAR","lpDevice","in"],
			["DWORD","iDevNum","in"],
			["PBLOB","lpDisplayDevice","inout"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'user32', 'EnumDisplayDevicesW', 'BOOL',[
			["PWCHAR","lpDevice","in"],
			["DWORD","iDevNum","in"],
			["PBLOB","lpDisplayDevice","inout"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'user32', 'EnumDisplayMonitors', 'BOOL',[
			["DWORD","hdc","in"],
			["PBLOB","lprcClip","in"],
			["PBLOB","lpfnEnum","in"],
			["DWORD","dwData","in"],
			])

		railgun.add_function( 'user32', 'EnumDisplaySettingsA', 'BOOL',[
			["PCHAR","lpszDeviceName","in"],
			["DWORD","iModeNum","in"],
			["PBLOB","lpDevMode","out"],
			])

		railgun.add_function( 'user32', 'EnumDisplaySettingsExA', 'BOOL',[
			["PCHAR","lpszDeviceName","in"],
			["DWORD","iModeNum","in"],
			["PBLOB","lpDevMode","out"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'user32', 'EnumDisplaySettingsExW', 'BOOL',[
			["PWCHAR","lpszDeviceName","in"],
			["DWORD","iModeNum","in"],
			["PBLOB","lpDevMode","out"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'user32', 'EnumDisplaySettingsW', 'BOOL',[
			["PWCHAR","lpszDeviceName","in"],
			["DWORD","iModeNum","in"],
			["PBLOB","lpDevMode","out"],
			])

		railgun.add_function( 'user32', 'EnumPropsA', 'DWORD',[
			["DWORD","hWnd","in"],
			["PBLOB","lpEnumFunc","in"],
			])

		railgun.add_function( 'user32', 'EnumPropsExA', 'DWORD',[
			["DWORD","hWnd","in"],
			["PBLOB","lpEnumFunc","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'EnumPropsExW', 'DWORD',[
			["DWORD","hWnd","in"],
			["PBLOB","lpEnumFunc","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'EnumPropsW', 'DWORD',[
			["DWORD","hWnd","in"],
			["PBLOB","lpEnumFunc","in"],
			])

		railgun.add_function( 'user32', 'EnumThreadWindows', 'BOOL',[
			["DWORD","dwThreadId","in"],
			["PBLOB","lpfn","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'EnumWindowStationsA', 'BOOL',[
			["PBLOB","lpEnumFunc","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'EnumWindowStationsW', 'BOOL',[
			["PBLOB","lpEnumFunc","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'EnumWindows', 'BOOL',[
			["PBLOB","lpEnumFunc","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'EqualRect', 'BOOL',[
			["PBLOB","lprc1","in"],
			["PBLOB","lprc2","in"],
			])

		railgun.add_function( 'user32', 'ExcludeUpdateRgn', 'DWORD',[
			["DWORD","hDC","in"],
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'ExitWindowsEx', 'BOOL',[
			["DWORD","uFlags","in"],
			["DWORD","dwReason","in"],
			])

		railgun.add_function( 'user32', 'FillRect', 'DWORD',[
			["DWORD","hDC","in"],
			["PBLOB","lprc","in"],
			["DWORD","hbr","in"],
			])

		railgun.add_function( 'user32', 'FindWindowA', 'DWORD',[
			["PCHAR","lpClassName","in"],
			["PCHAR","lpWindowName","in"],
			])

		railgun.add_function( 'user32', 'FindWindowExA', 'DWORD',[
			["DWORD","hWndParent","in"],
			["DWORD","hWndChildAfter","in"],
			["PCHAR","lpszClass","in"],
			["PCHAR","lpszWindow","in"],
			])

		railgun.add_function( 'user32', 'FindWindowExW', 'DWORD',[
			["DWORD","hWndParent","in"],
			["DWORD","hWndChildAfter","in"],
			["PWCHAR","lpszClass","in"],
			["PWCHAR","lpszWindow","in"],
			])

		railgun.add_function( 'user32', 'FindWindowW', 'DWORD',[
			["PWCHAR","lpClassName","in"],
			["PWCHAR","lpWindowName","in"],
			])

		railgun.add_function( 'user32', 'FlashWindow', 'BOOL',[
			["DWORD","hWnd","in"],
			["BOOL","bInvert","in"],
			])

		railgun.add_function( 'user32', 'FlashWindowEx', 'BOOL',[
			["PBLOB","pfwi","in"],
			])

		railgun.add_function( 'user32', 'FrameRect', 'DWORD',[
			["DWORD","hDC","in"],
			["PBLOB","lprc","in"],
			["DWORD","hbr","in"],
			])

		railgun.add_function( 'user32', 'GetActiveWindow', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetAltTabInfoA', 'BOOL',[
			["DWORD","hwnd","in"],
			["DWORD","iItem","in"],
			["PBLOB","pati","inout"],
			["PCHAR","pszItemText","out"],
			["DWORD","cchItemText","in"],
			])

		railgun.add_function( 'user32', 'GetAltTabInfoW', 'BOOL',[
			["DWORD","hwnd","in"],
			["DWORD","iItem","in"],
			["PBLOB","pati","inout"],
			["PWCHAR","pszItemText","out"],
			["DWORD","cchItemText","in"],
			])

		railgun.add_function( 'user32', 'GetAncestor', 'DWORD',[
			["DWORD","hwnd","in"],
			["DWORD","gaFlags","in"],
			])

		railgun.add_function( 'user32', 'GetAsyncKeyState', 'WORD',[
			["DWORD","vKey","in"],
			])

		railgun.add_function( 'user32', 'GetCapture', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetCaretBlinkTime', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetCaretPos', 'BOOL',[
			["PBLOB","lpPoint","out"],
			])

		railgun.add_function( 'user32', 'GetClassInfoA', 'BOOL',[
			["DWORD","hInstance","in"],
			["PCHAR","lpClassName","in"],
			["PBLOB","lpWndClass","out"],
			])

		railgun.add_function( 'user32', 'GetClassInfoExA', 'BOOL',[
			["DWORD","hInstance","in"],
			["PCHAR","lpszClass","in"],
			["PBLOB","lpwcx","out"],
			])

		railgun.add_function( 'user32', 'GetClassInfoExW', 'BOOL',[
			["DWORD","hInstance","in"],
			["PWCHAR","lpszClass","in"],
			["PBLOB","lpwcx","out"],
			])

		railgun.add_function( 'user32', 'GetClassInfoW', 'BOOL',[
			["DWORD","hInstance","in"],
			["PWCHAR","lpClassName","in"],
			["PBLOB","lpWndClass","out"],
			])

		railgun.add_function( 'user32', 'GetClassLongA', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","nIndex","in"],
			])

		railgun.add_function( 'user32', 'GetClassLongW', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","nIndex","in"],
			])

		railgun.add_function( 'user32', 'GetClassNameA', 'DWORD',[
			["DWORD","hWnd","in"],
			["PCHAR","lpClassName","out"],
			["DWORD","nMaxCount","in"],
			])

		railgun.add_function( 'user32', 'GetClassNameW', 'DWORD',[
			["DWORD","hWnd","in"],
			["PWCHAR","lpClassName","out"],
			["DWORD","nMaxCount","in"],
			])

		railgun.add_function( 'user32', 'GetClassWord', 'WORD',[
			["DWORD","hWnd","in"],
			["DWORD","nIndex","in"],
			])

		railgun.add_function( 'user32', 'GetClientRect', 'BOOL',[
			["DWORD","hWnd","in"],
			["PBLOB","lpRect","out"],
			])

		railgun.add_function( 'user32', 'GetClipCursor', 'BOOL',[
			["PBLOB","lpRect","out"],
			])

		railgun.add_function( 'user32', 'GetClipboardData', 'DWORD',[
			["DWORD","uFormat","in"],
			])

		railgun.add_function( 'user32', 'GetClipboardFormatNameA', 'DWORD',[
			["DWORD","format","in"],
			["PCHAR","lpszFormatName","out"],
			["DWORD","cchMaxCount","in"],
			])

		railgun.add_function( 'user32', 'GetClipboardFormatNameW', 'DWORD',[
			["DWORD","format","in"],
			["PWCHAR","lpszFormatName","out"],
			["DWORD","cchMaxCount","in"],
			])

		railgun.add_function( 'user32', 'GetClipboardOwner', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetClipboardSequenceNumber', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetClipboardViewer', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetComboBoxInfo', 'BOOL',[
			["DWORD","hwndCombo","in"],
			["PBLOB","pcbi","inout"],
			])

		railgun.add_function( 'user32', 'GetCursor', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetCursorInfo', 'BOOL',[
			["PBLOB","pci","inout"],
			])

		railgun.add_function( 'user32', 'GetCursorPos', 'BOOL',[
			["PBLOB","lpPoint","out"],
			])

		railgun.add_function( 'user32', 'GetDC', 'DWORD',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'GetDCEx', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","hrgnClip","in"],
			["DWORD","flags","in"],
			])

		railgun.add_function( 'user32', 'GetDesktopWindow', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetDialogBaseUnits', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetDlgCtrlID', 'DWORD',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'GetDlgItem', 'DWORD',[
			["DWORD","hDlg","in"],
			["DWORD","nIDDlgItem","in"],
			])

		railgun.add_function( 'user32', 'GetDlgItemInt', 'DWORD',[
			["DWORD","hDlg","in"],
			["DWORD","nIDDlgItem","in"],
			["PBLOB","lpTranslated","out"],
			["BOOL","bSigned","in"],
			])

		railgun.add_function( 'user32', 'GetDlgItemTextA', 'DWORD',[
			["DWORD","hDlg","in"],
			["DWORD","nIDDlgItem","in"],
			["PCHAR","lpString","out"],
			["DWORD","cchMax","in"],
			])

		railgun.add_function( 'user32', 'GetDlgItemTextW', 'DWORD',[
			["DWORD","hDlg","in"],
			["DWORD","nIDDlgItem","in"],
			["PWCHAR","lpString","out"],
			["DWORD","cchMax","in"],
			])

		railgun.add_function( 'user32', 'GetDoubleClickTime', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetFocus', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetForegroundWindow', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetGUIThreadInfo', 'BOOL',[
			["DWORD","idThread","in"],
			["PBLOB","pgui","inout"],
			])

		railgun.add_function( 'user32', 'GetGuiResources', 'DWORD',[
			["DWORD","hProcess","in"],
			["DWORD","uiFlags","in"],
			])

		railgun.add_function( 'user32', 'GetIconInfo', 'BOOL',[
			["DWORD","hIcon","in"],
			["PBLOB","piconinfo","out"],
			])

		railgun.add_function( 'user32', 'GetInputState', 'BOOL',[
			])

		railgun.add_function( 'user32', 'GetKBCodePage', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetKeyNameTextA', 'DWORD',[
			["DWORD","lParam","in"],
			["PCHAR","lpString","out"],
			["DWORD","cchSize","in"],
			])

		railgun.add_function( 'user32', 'GetKeyNameTextW', 'DWORD',[
			["DWORD","lParam","in"],
			["PWCHAR","lpString","out"],
			["DWORD","cchSize","in"],
			])

		railgun.add_function( 'user32', 'GetKeyState', 'WORD',[
			["DWORD","nVirtKey","in"],
			])

		railgun.add_function( 'user32', 'GetKeyboardLayout', 'DWORD',[
			["DWORD","idThread","in"],
			])

		railgun.add_function( 'user32', 'GetKeyboardType', 'DWORD',[
			["DWORD","nTypeFlag","in"],
			])

		railgun.add_function( 'user32', 'GetLastActivePopup', 'DWORD',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'GetLastInputInfo', 'BOOL',[
			["PBLOB","plii","out"],
			])

		railgun.add_function( 'user32', 'GetLayeredWindowAttributes', 'BOOL',[
			["DWORD","hwnd","in"],
			["PDWORD","pcrKey","out"],
			["PBLOB","pbAlpha","out"],
			["PDWORD","pdwFlags","out"],
			])

		railgun.add_function( 'user32', 'GetListBoxInfo', 'DWORD',[
			["DWORD","hwnd","in"],
			])

		railgun.add_function( 'user32', 'GetMenu', 'DWORD',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'GetMenuBarInfo', 'BOOL',[
			["DWORD","hwnd","in"],
			["DWORD","idObject","in"],
			["DWORD","idItem","in"],
			["PBLOB","pmbi","inout"],
			])

		railgun.add_function( 'user32', 'GetMenuCheckMarkDimensions', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetMenuDefaultItem', 'DWORD',[
			["DWORD","hMenu","in"],
			["DWORD","fByPos","in"],
			["DWORD","gmdiFlags","in"],
			])

		railgun.add_function( 'user32', 'GetMenuInfo', 'BOOL',[
			["DWORD","param0","in"],
			["PBLOB","param1","inout"],
			])

		railgun.add_function( 'user32', 'GetMenuItemCount', 'DWORD',[
			["DWORD","hMenu","in"],
			])

		railgun.add_function( 'user32', 'GetMenuItemID', 'DWORD',[
			["DWORD","hMenu","in"],
			["DWORD","nPos","in"],
			])

		railgun.add_function( 'user32', 'GetMenuItemInfoA', 'BOOL',[
			["DWORD","hmenu","in"],
			["DWORD","item","in"],
			["BOOL","fByPosition","in"],
			["PBLOB","lpmii","inout"],
			])

		railgun.add_function( 'user32', 'GetMenuItemInfoW', 'BOOL',[
			["DWORD","hmenu","in"],
			["DWORD","item","in"],
			["BOOL","fByPosition","in"],
			["PBLOB","lpmii","inout"],
			])

		railgun.add_function( 'user32', 'GetMenuItemRect', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","hMenu","in"],
			["DWORD","uItem","in"],
			["PBLOB","lprcItem","out"],
			])

		railgun.add_function( 'user32', 'GetMenuState', 'DWORD',[
			["DWORD","hMenu","in"],
			["DWORD","uId","in"],
			["DWORD","uFlags","in"],
			])

		railgun.add_function( 'user32', 'GetMenuStringA', 'DWORD',[
			["DWORD","hMenu","in"],
			["DWORD","uIDItem","in"],
			["PCHAR","lpString","out"],
			["DWORD","cchMax","in"],
			["DWORD","flags","in"],
			])

		railgun.add_function( 'user32', 'GetMenuStringW', 'DWORD',[
			["DWORD","hMenu","in"],
			["DWORD","uIDItem","in"],
			["PWCHAR","lpString","out"],
			["DWORD","cchMax","in"],
			["DWORD","flags","in"],
			])

		railgun.add_function( 'user32', 'GetMessageA', 'BOOL',[
			["PBLOB","lpMsg","out"],
			["DWORD","hWnd","in"],
			["DWORD","wMsgFilterMin","in"],
			["DWORD","wMsgFilterMax","in"],
			])

		railgun.add_function( 'user32', 'GetMessageExtraInfo', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetMessagePos', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetMessageTime', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetMessageW', 'BOOL',[
			["PBLOB","lpMsg","out"],
			["DWORD","hWnd","in"],
			["DWORD","wMsgFilterMin","in"],
			["DWORD","wMsgFilterMax","in"],
			])

		railgun.add_function( 'user32', 'GetMonitorInfoA', 'BOOL',[
			["DWORD","hMonitor","in"],
			["PBLOB","lpmi","inout"],
			])

		railgun.add_function( 'user32', 'GetMonitorInfoW', 'BOOL',[
			["DWORD","hMonitor","in"],
			["PBLOB","lpmi","inout"],
			])

		railgun.add_function( 'user32', 'GetMouseMovePointsEx', 'DWORD',[
			["DWORD","cbSize","in"],
			["PBLOB","lppt","in"],
			["PBLOB","lpptBuf","out"],
			["DWORD","nBufPoints","in"],
			["DWORD","resolution","in"],
			])

		railgun.add_function( 'user32', 'GetNextDlgGroupItem', 'DWORD',[
			["DWORD","hDlg","in"],
			["DWORD","hCtl","in"],
			["BOOL","bPrevious","in"],
			])

		railgun.add_function( 'user32', 'GetNextDlgTabItem', 'DWORD',[
			["DWORD","hDlg","in"],
			["DWORD","hCtl","in"],
			["BOOL","bPrevious","in"],
			])

		railgun.add_function( 'user32', 'GetOpenClipboardWindow', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetParent', 'DWORD',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'GetPriorityClipboardFormat', 'DWORD',[
			["PDWORD","paFormatPriorityList","in"],
			["DWORD","cFormats","in"],
			])

		railgun.add_function( 'user32', 'GetProcessDefaultLayout', 'BOOL',[
			["PDWORD","pdwDefaultLayout","out"],
			])

		railgun.add_function( 'user32', 'GetProcessWindowStation', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetPropA', 'DWORD',[
			["DWORD","hWnd","in"],
			["PCHAR","lpString","in"],
			])

		railgun.add_function( 'user32', 'GetPropW', 'DWORD',[
			["DWORD","hWnd","in"],
			["PWCHAR","lpString","in"],
			])

		railgun.add_function( 'user32', 'GetQueueStatus', 'DWORD',[
			["DWORD","flags","in"],
			])

		railgun.add_function( 'user32', 'GetRawInputBuffer', 'DWORD',[
			["PBLOB","pData","out"],
			["PDWORD","pcbSize","inout"],
			["DWORD","cbSizeHeader","in"],
			])

		railgun.add_function( 'user32', 'GetRawInputData', 'DWORD',[
			["DWORD","hRawInput","in"],
			["DWORD","uiCommand","in"],
			["PBLOB","pData","out"],
			["PDWORD","pcbSize","inout"],
			["DWORD","cbSizeHeader","in"],
			])

		railgun.add_function( 'user32', 'GetRawInputDeviceInfoA', 'DWORD',[
			["DWORD","hDevice","in"],
			["DWORD","uiCommand","in"],
			["PBLOB","pData","inout"],
			["PDWORD","pcbSize","inout"],
			])

		railgun.add_function( 'user32', 'GetRawInputDeviceInfoW', 'DWORD',[
			["DWORD","hDevice","in"],
			["DWORD","uiCommand","in"],
			["PBLOB","pData","inout"],
			["PDWORD","pcbSize","inout"],
			])

		railgun.add_function( 'user32', 'GetRawInputDeviceList', 'DWORD',[
			["PBLOB","pRawInputDeviceList","out"],
			["PDWORD","puiNumDevices","inout"],
			["DWORD","cbSize","in"],
			])

		railgun.add_function( 'user32', 'GetRegisteredRawInputDevices', 'DWORD',[
			["PBLOB","pRawInputDevices","out"],
			["PDWORD","puiNumDevices","inout"],
			["DWORD","cbSize","in"],
			])

		railgun.add_function( 'user32', 'GetScrollBarInfo', 'BOOL',[
			["DWORD","hwnd","in"],
			["DWORD","idObject","in"],
			["PBLOB","psbi","inout"],
			])

		railgun.add_function( 'user32', 'GetScrollInfo', 'BOOL',[
			["DWORD","hwnd","in"],
			["DWORD","nBar","in"],
			["PBLOB","lpsi","inout"],
			])

		railgun.add_function( 'user32', 'GetScrollPos', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","nBar","in"],
			])

		railgun.add_function( 'user32', 'GetScrollRange', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","nBar","in"],
			["PDWORD","lpMinPos","out"],
			["PDWORD","lpMaxPos","out"],
			])

		railgun.add_function( 'user32', 'GetShellWindow', 'DWORD',[
			])

		railgun.add_function( 'user32', 'GetSubMenu', 'DWORD',[
			["DWORD","hMenu","in"],
			["DWORD","nPos","in"],
			])

		railgun.add_function( 'user32', 'GetSysColor', 'DWORD',[
			["DWORD","nIndex","in"],
			])

		railgun.add_function( 'user32', 'GetSysColorBrush', 'DWORD',[
			["DWORD","nIndex","in"],
			])

		railgun.add_function( 'user32', 'GetSystemMenu', 'DWORD',[
			["DWORD","hWnd","in"],
			["BOOL","bRevert","in"],
			])

		railgun.add_function( 'user32', 'GetSystemMetrics', 'DWORD',[
			["DWORD","nIndex","in"],
			])

		railgun.add_function( 'user32', 'GetThreadDesktop', 'DWORD',[
			["DWORD","dwThreadId","in"],
			])

		railgun.add_function( 'user32', 'GetTitleBarInfo', 'BOOL',[
			["DWORD","hwnd","in"],
			["PBLOB","pti","inout"],
			])

		railgun.add_function( 'user32', 'GetTopWindow', 'DWORD',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'GetUpdateRect', 'BOOL',[
			["DWORD","hWnd","in"],
			["PBLOB","lpRect","out"],
			["BOOL","bErase","in"],
			])

		railgun.add_function( 'user32', 'GetUpdateRgn', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","hRgn","in"],
			["BOOL","bErase","in"],
			])

		railgun.add_function( 'user32', 'GetUserObjectInformationA', 'BOOL',[
			["DWORD","hObj","in"],
			["DWORD","nIndex","in"],
			["PBLOB","pvInfo","out"],
			["DWORD","nLength","in"],
			["PDWORD","lpnLengthNeeded","out"],
			])

		railgun.add_function( 'user32', 'GetUserObjectInformationW', 'BOOL',[
			["DWORD","hObj","in"],
			["DWORD","nIndex","in"],
			["PBLOB","pvInfo","out"],
			["DWORD","nLength","in"],
			["PDWORD","lpnLengthNeeded","out"],
			])

		railgun.add_function( 'user32', 'GetUserObjectSecurity', 'BOOL',[
			["DWORD","hObj","in"],
			["PBLOB","pSIRequested","in"],
			["PBLOB","pSID","out"],
			["DWORD","nLength","in"],
			["PDWORD","lpnLengthNeeded","out"],
			])

		railgun.add_function( 'user32', 'GetWindow', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","uCmd","in"],
			])

		railgun.add_function( 'user32', 'GetWindowContextHelpId', 'DWORD',[
			["DWORD","param0","in"],
			])

		railgun.add_function( 'user32', 'GetWindowDC', 'DWORD',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'GetWindowInfo', 'BOOL',[
			["DWORD","hwnd","in"],
			["PBLOB","pwi","inout"],
			])

		railgun.add_function( 'user32', 'GetWindowLongA', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","nIndex","in"],
			])

		railgun.add_function( 'user32', 'GetWindowLongW', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","nIndex","in"],
			])

		railgun.add_function( 'user32', 'GetWindowModuleFileNameA', 'DWORD',[
			["DWORD","hwnd","in"],
			["PCHAR","pszFileName","out"],
			["DWORD","cchFileNameMax","in"],
			])

		railgun.add_function( 'user32', 'GetWindowModuleFileNameW', 'DWORD',[
			["DWORD","hwnd","in"],
			["PWCHAR","pszFileName","out"],
			["DWORD","cchFileNameMax","in"],
			])

		railgun.add_function( 'user32', 'GetWindowPlacement', 'BOOL',[
			["DWORD","hWnd","in"],
			["PBLOB","lpwndpl","inout"],
			])

		railgun.add_function( 'user32', 'GetWindowRect', 'BOOL',[
			["DWORD","hWnd","in"],
			["PBLOB","lpRect","out"],
			])

		railgun.add_function( 'user32', 'GetWindowRgn', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","hRgn","in"],
			])

		railgun.add_function( 'user32', 'GetWindowRgnBox', 'DWORD',[
			["DWORD","hWnd","in"],
			["PBLOB","lprc","out"],
			])

		railgun.add_function( 'user32', 'GetWindowTextA', 'DWORD',[
			["DWORD","hWnd","in"],
			["PCHAR","lpString","out"],
			["DWORD","nMaxCount","in"],
			])

		railgun.add_function( 'user32', 'GetWindowTextLengthA', 'DWORD',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'GetWindowTextLengthW', 'DWORD',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'GetWindowTextW', 'DWORD',[
			["DWORD","hWnd","in"],
			["PWCHAR","lpString","out"],
			["DWORD","nMaxCount","in"],
			])

		railgun.add_function( 'user32', 'GetWindowThreadProcessId', 'DWORD',[
			["DWORD","hWnd","in"],
			["PDWORD","lpdwProcessId","out"],
			])

		railgun.add_function( 'user32', 'GetWindowWord', 'WORD',[
			["DWORD","hWnd","in"],
			["DWORD","nIndex","in"],
			])

		railgun.add_function( 'user32', 'GrayStringA', 'BOOL',[
			["DWORD","hDC","in"],
			["DWORD","hBrush","in"],
			["PBLOB","lpOutputFunc","in"],
			["DWORD","lpData","in"],
			["DWORD","nCount","in"],
			["DWORD","X","in"],
			["DWORD","Y","in"],
			["DWORD","nWidth","in"],
			["DWORD","nHeight","in"],
			])

		railgun.add_function( 'user32', 'GrayStringW', 'BOOL',[
			["DWORD","hDC","in"],
			["DWORD","hBrush","in"],
			["PBLOB","lpOutputFunc","in"],
			["DWORD","lpData","in"],
			["DWORD","nCount","in"],
			["DWORD","X","in"],
			["DWORD","Y","in"],
			["DWORD","nWidth","in"],
			["DWORD","nHeight","in"],
			])

		railgun.add_function( 'user32', 'HideCaret', 'BOOL',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'HiliteMenuItem', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","hMenu","in"],
			["DWORD","uIDHiliteItem","in"],
			["DWORD","uHilite","in"],
			])

		railgun.add_function( 'user32', 'InSendMessage', 'BOOL',[
			])

		railgun.add_function( 'user32', 'InSendMessageEx', 'DWORD',[
			["PBLOB","lpReserved","inout"],
			])

		railgun.add_function( 'user32', 'InflateRect', 'BOOL',[
			["PBLOB","lprc","inout"],
			["DWORD","dx","in"],
			["DWORD","dy","in"],
			])

		railgun.add_function( 'user32', 'InsertMenuA', 'BOOL',[
			["DWORD","hMenu","in"],
			["DWORD","uPosition","in"],
			["DWORD","uFlags","in"],
			["DWORD","uIDNewItem","in"],
			["PCHAR","lpNewItem","in"],
			])

		railgun.add_function( 'user32', 'InsertMenuItemW', 'BOOL',[
			["DWORD","hmenu","in"],
			["DWORD","item","in"],
			["BOOL","fByPosition","in"],
			["PBLOB","lpmi","in"],
			])

		railgun.add_function( 'user32', 'InsertMenuW', 'BOOL',[
			["DWORD","hMenu","in"],
			["DWORD","uPosition","in"],
			["DWORD","uFlags","in"],
			["DWORD","uIDNewItem","in"],
			["PWCHAR","lpNewItem","in"],
			])

		railgun.add_function( 'user32', 'InternalGetWindowText', 'DWORD',[
			["DWORD","hWnd","in"],
			["PWCHAR","pString","out"],
			["DWORD","cchMaxCount","in"],
			])

		railgun.add_function( 'user32', 'IntersectRect', 'BOOL',[
			["PBLOB","lprcDst","out"],
			["PBLOB","lprcSrc1","in"],
			["PBLOB","lprcSrc2","in"],
			])

		railgun.add_function( 'user32', 'InvalidateRect', 'BOOL',[
			["DWORD","hWnd","in"],
			["PBLOB","lpRect","in"],
			["BOOL","bErase","in"],
			])

		railgun.add_function( 'user32', 'InvalidateRgn', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","hRgn","in"],
			["BOOL","bErase","in"],
			])

		railgun.add_function( 'user32', 'InvertRect', 'BOOL',[
			["DWORD","hDC","in"],
			["PBLOB","lprc","in"],
			])

		railgun.add_function( 'user32', 'IsCharAlphaA', 'BOOL',[
			["BYTE","ch","in"],
			])

		railgun.add_function( 'user32', 'IsCharAlphaNumericA', 'BOOL',[
			["BYTE","ch","in"],
			])

		railgun.add_function( 'user32', 'IsCharAlphaNumericW', 'BOOL',[
			["WORD","ch","in"],
			])

		railgun.add_function( 'user32', 'IsCharAlphaW', 'BOOL',[
			["WORD","ch","in"],
			])

		railgun.add_function( 'user32', 'IsCharLowerA', 'BOOL',[
			["BYTE","ch","in"],
			])

		railgun.add_function( 'user32', 'IsCharLowerW', 'BOOL',[
			["WORD","ch","in"],
			])

		railgun.add_function( 'user32', 'IsCharUpperA', 'BOOL',[
			["BYTE","ch","in"],
			])

		railgun.add_function( 'user32', 'IsCharUpperW', 'BOOL',[
			["WORD","ch","in"],
			])

		railgun.add_function( 'user32', 'IsChild', 'BOOL',[
			["DWORD","hWndParent","in"],
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'IsClipboardFormatAvailable', 'BOOL',[
			["DWORD","format","in"],
			])

		railgun.add_function( 'user32', 'IsDialogMessageA', 'BOOL',[
			["DWORD","hDlg","in"],
			["PBLOB","lpMsg","in"],
			])

		railgun.add_function( 'user32', 'IsDialogMessageW', 'BOOL',[
			["DWORD","hDlg","in"],
			["PBLOB","lpMsg","in"],
			])

		railgun.add_function( 'user32', 'IsDlgButtonChecked', 'DWORD',[
			["DWORD","hDlg","in"],
			["DWORD","nIDButton","in"],
			])

		railgun.add_function( 'user32', 'IsGUIThread', 'BOOL',[
			["BOOL","bConvert","in"],
			])

		railgun.add_function( 'user32', 'IsHungAppWindow', 'BOOL',[
			["DWORD","hwnd","in"],
			])

		railgun.add_function( 'user32', 'IsIconic', 'BOOL',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'IsMenu', 'BOOL',[
			["DWORD","hMenu","in"],
			])

		railgun.add_function( 'user32', 'IsRectEmpty', 'BOOL',[
			["PBLOB","lprc","in"],
			])

		railgun.add_function( 'user32', 'IsWinEventHookInstalled', 'BOOL',[
			["DWORD","event","in"],
			])

		railgun.add_function( 'user32', 'IsWindow', 'BOOL',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'IsWindowEnabled', 'BOOL',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'IsWindowUnicode', 'BOOL',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'IsWindowVisible', 'BOOL',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'IsWow64Message', 'BOOL',[
			])

		railgun.add_function( 'user32', 'IsZoomed', 'BOOL',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'KillTimer', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","uIDEvent","in"],
			])

		railgun.add_function( 'user32', 'LoadAcceleratorsA', 'DWORD',[
			["DWORD","hInstance","in"],
			["PCHAR","lpTableName","in"],
			])

		railgun.add_function( 'user32', 'LoadAcceleratorsW', 'DWORD',[
			["DWORD","hInstance","in"],
			["PWCHAR","lpTableName","in"],
			])

		railgun.add_function( 'user32', 'LoadBitmapA', 'DWORD',[
			["DWORD","hInstance","in"],
			["PCHAR","lpBitmapName","in"],
			])

		railgun.add_function( 'user32', 'LoadBitmapW', 'DWORD',[
			["DWORD","hInstance","in"],
			["PWCHAR","lpBitmapName","in"],
			])

		railgun.add_function( 'user32', 'LoadCursorA', 'DWORD',[
			["DWORD","hInstance","in"],
			["PCHAR","lpCursorName","in"],
			])

		railgun.add_function( 'user32', 'LoadCursorFromFileA', 'DWORD',[
			["PCHAR","lpFileName","in"],
			])

		railgun.add_function( 'user32', 'LoadCursorFromFileW', 'DWORD',[
			["PWCHAR","lpFileName","in"],
			])

		railgun.add_function( 'user32', 'LoadCursorW', 'DWORD',[
			["DWORD","hInstance","in"],
			["PWCHAR","lpCursorName","in"],
			])

		railgun.add_function( 'user32', 'LoadIconA', 'DWORD',[
			["DWORD","hInstance","in"],
			["PCHAR","lpIconName","in"],
			])

		railgun.add_function( 'user32', 'LoadIconW', 'DWORD',[
			["DWORD","hInstance","in"],
			["PWCHAR","lpIconName","in"],
			])

		railgun.add_function( 'user32', 'LoadImageA', 'DWORD',[
			["DWORD","hInst","in"],
			["PCHAR","name","in"],
			["DWORD","type","in"],
			["DWORD","cx","in"],
			["DWORD","cy","in"],
			["DWORD","fuLoad","in"],
			])

		railgun.add_function( 'user32', 'LoadImageW', 'DWORD',[
			["DWORD","hInst","in"],
			["PWCHAR","name","in"],
			["DWORD","type","in"],
			["DWORD","cx","in"],
			["DWORD","cy","in"],
			["DWORD","fuLoad","in"],
			])

		railgun.add_function( 'user32', 'LoadKeyboardLayoutA', 'DWORD',[
			["PCHAR","pwszKLID","in"],
			["DWORD","Flags","in"],
			])

		railgun.add_function( 'user32', 'LoadKeyboardLayoutW', 'DWORD',[
			["PWCHAR","pwszKLID","in"],
			["DWORD","Flags","in"],
			])

		railgun.add_function( 'user32', 'LoadMenuA', 'DWORD',[
			["DWORD","hInstance","in"],
			["PCHAR","lpMenuName","in"],
			])

		railgun.add_function( 'user32', 'LoadMenuIndirectA', 'DWORD',[
			["PBLOB","lpMenuTemplate","in"],
			])

		railgun.add_function( 'user32', 'LoadMenuIndirectW', 'DWORD',[
			["PBLOB","lpMenuTemplate","in"],
			])

		railgun.add_function( 'user32', 'LoadMenuW', 'DWORD',[
			["DWORD","hInstance","in"],
			["PWCHAR","lpMenuName","in"],
			])

		railgun.add_function( 'user32', 'LoadStringA', 'DWORD',[
			["DWORD","hInstance","in"],
			["DWORD","uID","in"],
			["PCHAR","lpBuffer","out"],
			["DWORD","cchBufferMax","in"],
			])

		railgun.add_function( 'user32', 'LoadStringW', 'DWORD',[
			["DWORD","hInstance","in"],
			["DWORD","uID","in"],
			["PWCHAR","lpBuffer","out"],
			["DWORD","cchBufferMax","in"],
			])

		railgun.add_function( 'user32', 'LockSetForegroundWindow', 'BOOL',[
			["DWORD","uLockCode","in"],
			])

		railgun.add_function( 'user32', 'LockWindowUpdate', 'BOOL',[
			["DWORD","hWndLock","in"],
			])

		railgun.add_function( 'user32', 'LockWorkStation', 'BOOL',[
			])

		railgun.add_function( 'user32', 'LookupIconIdFromDirectory', 'DWORD',[
			["PBLOB","presbits","in"],
			["BOOL","fIcon","in"],
			])

		railgun.add_function( 'user32', 'LookupIconIdFromDirectoryEx', 'DWORD',[
			["PBLOB","presbits","in"],
			["BOOL","fIcon","in"],
			["DWORD","cxDesired","in"],
			["DWORD","cyDesired","in"],
			["DWORD","Flags","in"],
			])

		railgun.add_function( 'user32', 'MapDialogRect', 'BOOL',[
			["DWORD","hDlg","in"],
			["PBLOB","lpRect","inout"],
			])

		railgun.add_function( 'user32', 'MapVirtualKeyA', 'DWORD',[
			["DWORD","uCode","in"],
			["DWORD","uMapType","in"],
			])

		railgun.add_function( 'user32', 'MapVirtualKeyExA', 'DWORD',[
			["DWORD","uCode","in"],
			["DWORD","uMapType","in"],
			["DWORD","dwhkl","in"],
			])

		railgun.add_function( 'user32', 'MapVirtualKeyExW', 'DWORD',[
			["DWORD","uCode","in"],
			["DWORD","uMapType","in"],
			["DWORD","dwhkl","in"],
			])

		railgun.add_function( 'user32', 'MapVirtualKeyW', 'DWORD',[
			["DWORD","uCode","in"],
			["DWORD","uMapType","in"],
			])

		railgun.add_function( 'user32', 'MapWindowPoints', 'DWORD',[
			["DWORD","hWndFrom","in"],
			["DWORD","hWndTo","in"],
			["PBLOB","lpPoints","in"],
			["DWORD","cPoints","in"],
			])

		railgun.add_function( 'user32', 'MenuItemFromPoint', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","hMenu","in"],
			["PBLOB","ptScreen","in"],
			])

		railgun.add_function( 'user32', 'MessageBeep', 'BOOL',[
			["DWORD","uType","in"],
			])

		railgun.add_function( 'user32', 'MessageBoxA', 'DWORD',[
			["DWORD","hWnd","in"],
			["PCHAR","lpText","in"],
			["PCHAR","lpCaption","in"],
			["DWORD","uType","in"],
			])

		railgun.add_function( 'user32', 'MessageBoxExA', 'DWORD',[
			["DWORD","hWnd","in"],
			["PCHAR","lpText","in"],
			["PCHAR","lpCaption","in"],
			["DWORD","uType","in"],
			["WORD","wLanguageId","in"],
			])

		railgun.add_function( 'user32', 'MessageBoxExW', 'DWORD',[
			["DWORD","hWnd","in"],
			["PWCHAR","lpText","in"],
			["PWCHAR","lpCaption","in"],
			["DWORD","uType","in"],
			["WORD","wLanguageId","in"],
			])

		railgun.add_function( 'user32', 'MessageBoxIndirectA', 'DWORD',[
			["PBLOB","lpmbp","in"],
			])

		railgun.add_function( 'user32', 'MessageBoxIndirectW', 'DWORD',[
			["PBLOB","lpmbp","in"],
			])

		railgun.add_function( 'user32', 'MessageBoxW', 'DWORD',[
			["DWORD","hWnd","in"],
			["PWCHAR","lpText","in"],
			["PWCHAR","lpCaption","in"],
			["DWORD","uType","in"],
			])

		railgun.add_function( 'user32', 'ModifyMenuA', 'BOOL',[
			["DWORD","hMnu","in"],
			["DWORD","uPosition","in"],
			["DWORD","uFlags","in"],
			["DWORD","uIDNewItem","in"],
			["PCHAR","lpNewItem","in"],
			])

		railgun.add_function( 'user32', 'ModifyMenuW', 'BOOL',[
			["DWORD","hMnu","in"],
			["DWORD","uPosition","in"],
			["DWORD","uFlags","in"],
			["DWORD","uIDNewItem","in"],
			["PWCHAR","lpNewItem","in"],
			])

		railgun.add_function( 'user32', 'MonitorFromPoint', 'DWORD',[
			["PBLOB","pt","in"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'user32', 'MonitorFromRect', 'DWORD',[
			["PBLOB","lprc","in"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'user32', 'MonitorFromWindow', 'DWORD',[
			["DWORD","hwnd","in"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'user32', 'MoveWindow', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","X","in"],
			["DWORD","Y","in"],
			["DWORD","nWidth","in"],
			["DWORD","nHeight","in"],
			["BOOL","bRepaint","in"],
			])

		railgun.add_function( 'user32', 'MsgWaitForMultipleObjects', 'DWORD',[
			["DWORD","nCount","in"],
			["PDWORD","pHandles","in"],
			["BOOL","fWaitAll","in"],
			["DWORD","dwMilliseconds","in"],
			["DWORD","dwWakeMask","in"],
			])

		railgun.add_function( 'user32', 'MsgWaitForMultipleObjectsEx', 'DWORD',[
			["DWORD","nCount","in"],
			["PDWORD","pHandles","in"],
			["DWORD","dwMilliseconds","in"],
			["DWORD","dwWakeMask","in"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'user32', 'NotifyWinEvent', 'VOID',[
			["DWORD","event","in"],
			["DWORD","hwnd","in"],
			["DWORD","idObject","in"],
			["DWORD","idChild","in"],
			])

		railgun.add_function( 'user32', 'OemKeyScan', 'DWORD',[
			["WORD","wOemChar","in"],
			])

		railgun.add_function( 'user32', 'OemToCharA', 'BOOL',[
			["PCHAR","lpszSrc","in"],
			["PCHAR","lpszDst","out"],
			])

		railgun.add_function( 'user32', 'OemToCharBuffA', 'BOOL',[
			["PCHAR","lpszSrc","in"],
			["PCHAR","lpszDst","out"],
			["DWORD","cchDstLength","in"],
			])

		railgun.add_function( 'user32', 'OemToCharBuffW', 'BOOL',[
			["PCHAR","lpszSrc","in"],
			["PWCHAR","lpszDst","out"],
			["DWORD","cchDstLength","in"],
			])

		railgun.add_function( 'user32', 'OemToCharW', 'BOOL',[
			["PCHAR","lpszSrc","in"],
			["PWCHAR","lpszDst","out"],
			])

		railgun.add_function( 'user32', 'OffsetRect', 'BOOL',[
			["PBLOB","lprc","inout"],
			["DWORD","dx","in"],
			["DWORD","dy","in"],
			])

		railgun.add_function( 'user32', 'OpenClipboard', 'BOOL',[
			["DWORD","hWndNewOwner","in"],
			])

		railgun.add_function( 'user32', 'OpenDesktopA', 'DWORD',[
			["PCHAR","lpszDesktop","in"],
			["DWORD","dwFlags","in"],
			["BOOL","fInherit","in"],
			["DWORD","dwDesiredAccess","in"],
			])

		railgun.add_function( 'user32', 'OpenDesktopW', 'DWORD',[
			["PWCHAR","lpszDesktop","in"],
			["DWORD","dwFlags","in"],
			["BOOL","fInherit","in"],
			["DWORD","dwDesiredAccess","in"],
			])

		railgun.add_function( 'user32', 'OpenIcon', 'BOOL',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'OpenInputDesktop', 'DWORD',[
			["DWORD","dwFlags","in"],
			["BOOL","fInherit","in"],
			["DWORD","dwDesiredAccess","in"],
			])

		railgun.add_function( 'user32', 'OpenWindowStationA', 'DWORD',[
			["PCHAR","lpszWinSta","in"],
			["BOOL","fInherit","in"],
			["DWORD","dwDesiredAccess","in"],
			])

		railgun.add_function( 'user32', 'OpenWindowStationW', 'DWORD',[
			["PWCHAR","lpszWinSta","in"],
			["BOOL","fInherit","in"],
			["DWORD","dwDesiredAccess","in"],
			])

		railgun.add_function( 'user32', 'PaintDesktop', 'BOOL',[
			["DWORD","hdc","in"],
			])

		railgun.add_function( 'user32', 'PeekMessageA', 'BOOL',[
			["PBLOB","lpMsg","out"],
			["DWORD","hWnd","in"],
			["DWORD","wMsgFilterMin","in"],
			["DWORD","wMsgFilterMax","in"],
			["DWORD","wRemoveMsg","in"],
			])

		railgun.add_function( 'user32', 'PeekMessageW', 'BOOL',[
			["PBLOB","lpMsg","out"],
			["DWORD","hWnd","in"],
			["DWORD","wMsgFilterMin","in"],
			["DWORD","wMsgFilterMax","in"],
			["DWORD","wRemoveMsg","in"],
			])

		railgun.add_function( 'user32', 'PostMessageA', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'PostMessageW', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'PostQuitMessage', 'VOID',[
			["DWORD","nExitCode","in"],
			])

		railgun.add_function( 'user32', 'PostThreadMessageA', 'BOOL',[
			["DWORD","idThread","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'PostThreadMessageW', 'BOOL',[
			["DWORD","idThread","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'PrintWindow', 'BOOL',[
			["DWORD","hwnd","in"],
			["DWORD","hdcBlt","in"],
			["DWORD","nFlags","in"],
			])

		railgun.add_function( 'user32', 'PrivateExtractIconsA', 'DWORD',[
			["PCHAR","szFileName","in"],
			["DWORD","nIconIndex","in"],
			["DWORD","cxIcon","in"],
			["DWORD","cyIcon","in"],
			["PDWORD","phicon","out"],
			["PDWORD","piconid","out"],
			["DWORD","nIcons","in"],
			["DWORD","flags","in"],
			])

		railgun.add_function( 'user32', 'PrivateExtractIconsW', 'DWORD',[
			["PWCHAR","szFileName","in"],
			["DWORD","nIconIndex","in"],
			["DWORD","cxIcon","in"],
			["DWORD","cyIcon","in"],
			["PDWORD","phicon","out"],
			["PDWORD","piconid","out"],
			["DWORD","nIcons","in"],
			["DWORD","flags","in"],
			])

		railgun.add_function( 'user32', 'PtInRect', 'BOOL',[
			["PBLOB","lprc","in"],
			["PBLOB","pt","in"],
			])

		railgun.add_function( 'user32', 'RealChildWindowFromPoint', 'DWORD',[
			["DWORD","hwndParent","in"],
			["PBLOB","ptParentClientCoords","in"],
			])

		railgun.add_function( 'user32', 'RealGetWindowClassA', 'DWORD',[
			["DWORD","hwnd","in"],
			["PCHAR","ptszClassName","out"],
			["DWORD","cchClassNameMax","in"],
			])

		railgun.add_function( 'user32', 'RealGetWindowClassW', 'DWORD',[
			["DWORD","hwnd","in"],
			["PWCHAR","ptszClassName","out"],
			["DWORD","cchClassNameMax","in"],
			])

		railgun.add_function( 'user32', 'RedrawWindow', 'BOOL',[
			["DWORD","hWnd","in"],
			["PBLOB","lprcUpdate","in"],
			["DWORD","hrgnUpdate","in"],
			["DWORD","flags","in"],
			])

		railgun.add_function( 'user32', 'RegisterClassA', 'WORD',[
			["PBLOB","lpWndClass","in"],
			])

		railgun.add_function( 'user32', 'RegisterClassExA', 'WORD',[
			["PBLOB","param0","in"],
			])

		railgun.add_function( 'user32', 'RegisterClassExW', 'WORD',[
			["PBLOB","param0","in"],
			])

		railgun.add_function( 'user32', 'RegisterClassW', 'WORD',[
			["PBLOB","lpWndClass","in"],
			])

		railgun.add_function( 'user32', 'RegisterClipboardFormatA', 'DWORD',[
			["PCHAR","lpszFormat","in"],
			])

		railgun.add_function( 'user32', 'RegisterClipboardFormatW', 'DWORD',[
			["PWCHAR","lpszFormat","in"],
			])

		railgun.add_function( 'user32', 'RegisterDeviceNotificationA', 'DWORD',[
			["DWORD","hRecipient","in"],
			["PBLOB","NotificationFilter","in"],
			["DWORD","Flags","in"],
			])

		railgun.add_function( 'user32', 'RegisterDeviceNotificationW', 'DWORD',[
			["DWORD","hRecipient","in"],
			["PBLOB","NotificationFilter","in"],
			["DWORD","Flags","in"],
			])

		railgun.add_function( 'user32', 'RegisterHotKey', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","id","in"],
			["DWORD","fsModifiers","in"],
			["DWORD","vk","in"],
			])

		railgun.add_function( 'user32', 'RegisterRawInputDevices', 'BOOL',[
			["PBLOB","pRawInputDevices","in"],
			["DWORD","uiNumDevices","in"],
			["DWORD","cbSize","in"],
			])

		railgun.add_function( 'user32', 'RegisterShellHookWindow', 'BOOL',[
			["DWORD","hwnd","in"],
			])

		railgun.add_function( 'user32', 'RegisterWindowMessageA', 'DWORD',[
			["PCHAR","lpString","in"],
			])

		railgun.add_function( 'user32', 'RegisterWindowMessageW', 'DWORD',[
			["PWCHAR","lpString","in"],
			])

		railgun.add_function( 'user32', 'ReleaseCapture', 'BOOL',[
			])

		railgun.add_function( 'user32', 'ReleaseDC', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","hDC","in"],
			])

		railgun.add_function( 'user32', 'RemoveMenu', 'BOOL',[
			["DWORD","hMenu","in"],
			["DWORD","uPosition","in"],
			["DWORD","uFlags","in"],
			])

		railgun.add_function( 'user32', 'RemovePropA', 'DWORD',[
			["DWORD","hWnd","in"],
			["PCHAR","lpString","in"],
			])

		railgun.add_function( 'user32', 'RemovePropW', 'DWORD',[
			["DWORD","hWnd","in"],
			["PWCHAR","lpString","in"],
			])

		railgun.add_function( 'user32', 'ReplyMessage', 'BOOL',[
			["DWORD","lResult","in"],
			])

		railgun.add_function( 'user32', 'ScreenToClient', 'BOOL',[
			["DWORD","hWnd","in"],
			["PBLOB","lpPoint","inout"],
			])

		railgun.add_function( 'user32', 'ScrollDC', 'BOOL',[
			["DWORD","hDC","in"],
			["DWORD","dx","in"],
			["DWORD","dy","in"],
			["PBLOB","lprcScroll","in"],
			["PBLOB","lprcClip","in"],
			["DWORD","hrgnUpdate","in"],
			["PBLOB","lprcUpdate","out"],
			])

		railgun.add_function( 'user32', 'ScrollWindow', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","XAmount","in"],
			["DWORD","YAmount","in"],
			["PBLOB","lpRect","in"],
			["PBLOB","lpClipRect","in"],
			])

		railgun.add_function( 'user32', 'ScrollWindowEx', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","dx","in"],
			["DWORD","dy","in"],
			["PBLOB","prcScroll","in"],
			["PBLOB","prcClip","in"],
			["DWORD","hrgnUpdate","in"],
			["PBLOB","prcUpdate","out"],
			["DWORD","flags","in"],
			])

		railgun.add_function( 'user32', 'SendDlgItemMessageA', 'DWORD',[
			["DWORD","hDlg","in"],
			["DWORD","nIDDlgItem","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'SendDlgItemMessageW', 'DWORD',[
			["DWORD","hDlg","in"],
			["DWORD","nIDDlgItem","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'SendInput', 'DWORD',[
			["DWORD","cInputs","in"],
			["PBLOB","pInputs","in"],
			["DWORD","cbSize","in"],
			])

		railgun.add_function( 'user32', 'SendMessageA', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'SendMessageCallbackA', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			["PBLOB","lpResultCallBack","in"],
			["PDWORD","dwData","in"],
			])

		railgun.add_function( 'user32', 'SendMessageCallbackW', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			["PBLOB","lpResultCallBack","in"],
			["PDWORD","dwData","in"],
			])

		railgun.add_function( 'user32', 'SendMessageTimeoutA', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			["DWORD","fuFlags","in"],
			["DWORD","uTimeout","in"],
			["PBLOB","lpdwResult","out"],
			])

		railgun.add_function( 'user32', 'SendMessageTimeoutW', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			["DWORD","fuFlags","in"],
			["DWORD","uTimeout","in"],
			["PBLOB","lpdwResult","out"],
			])

		railgun.add_function( 'user32', 'SendMessageW', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'SendNotifyMessageA', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'SendNotifyMessageW', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","Msg","in"],
			["WORD","wParam","in"],
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'SetActiveWindow', 'DWORD',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'SetCapture', 'DWORD',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'SetCaretBlinkTime', 'BOOL',[
			["DWORD","uMSeconds","in"],
			])

		railgun.add_function( 'user32', 'SetCaretPos', 'BOOL',[
			["DWORD","X","in"],
			["DWORD","Y","in"],
			])

		railgun.add_function( 'user32', 'SetClassLongA', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","nIndex","in"],
			["DWORD","dwNewLong","in"],
			])

		railgun.add_function( 'user32', 'SetClassLongW', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","nIndex","in"],
			["DWORD","dwNewLong","in"],
			])

		railgun.add_function( 'user32', 'SetClassWord', 'WORD',[
			["DWORD","hWnd","in"],
			["DWORD","nIndex","in"],
			["WORD","wNewWord","in"],
			])

		railgun.add_function( 'user32', 'SetClipboardData', 'DWORD',[
			["DWORD","uFormat","in"],
			["DWORD","hMem","in"],
			])

		railgun.add_function( 'user32', 'SetClipboardViewer', 'DWORD',[
			["DWORD","hWndNewViewer","in"],
			])

		railgun.add_function( 'user32', 'SetCursor', 'DWORD',[
			["DWORD","hCursor","in"],
			])

		railgun.add_function( 'user32', 'SetCursorPos', 'BOOL',[
			["DWORD","X","in"],
			["DWORD","Y","in"],
			])

		railgun.add_function( 'user32', 'SetDebugErrorLevel', 'VOID',[
			["DWORD","dwLevel","in"],
			])

		railgun.add_function( 'user32', 'SetDlgItemInt', 'BOOL',[
			["DWORD","hDlg","in"],
			["DWORD","nIDDlgItem","in"],
			["DWORD","uValue","in"],
			["BOOL","bSigned","in"],
			])

		railgun.add_function( 'user32', 'SetDlgItemTextA', 'BOOL',[
			["DWORD","hDlg","in"],
			["DWORD","nIDDlgItem","in"],
			["PCHAR","lpString","in"],
			])

		railgun.add_function( 'user32', 'SetDlgItemTextW', 'BOOL',[
			["DWORD","hDlg","in"],
			["DWORD","nIDDlgItem","in"],
			["PWCHAR","lpString","in"],
			])

		railgun.add_function( 'user32', 'SetDoubleClickTime', 'BOOL',[
			["DWORD","param0","in"],
			])

		railgun.add_function( 'user32', 'SetFocus', 'DWORD',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'SetForegroundWindow', 'BOOL',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'SetLastErrorEx', 'VOID',[
			["DWORD","dwErrCode","in"],
			["DWORD","dwType","in"],
			])

		railgun.add_function( 'user32', 'SetLayeredWindowAttributes', 'BOOL',[
			["DWORD","hwnd","in"],
			["DWORD","crKey","in"],
			["BYTE","bAlpha","in"],
			["DWORD","dwFlags","in"],
			])

		railgun.add_function( 'user32', 'SetMenu', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","hMenu","in"],
			])

		railgun.add_function( 'user32', 'SetMenuContextHelpId', 'BOOL',[
			["DWORD","param0","in"],
			["DWORD","param1","in"],
			])

		railgun.add_function( 'user32', 'SetMenuDefaultItem', 'BOOL',[
			["DWORD","hMenu","in"],
			["DWORD","uItem","in"],
			["DWORD","fByPos","in"],
			])

		railgun.add_function( 'user32', 'SetMenuInfo', 'BOOL',[
			["DWORD","param0","in"],
			["PBLOB","param1","in"],
			])

		railgun.add_function( 'user32', 'SetMenuItemBitmaps', 'BOOL',[
			["DWORD","hMenu","in"],
			["DWORD","uPosition","in"],
			["DWORD","uFlags","in"],
			["DWORD","hBitmapUnchecked","in"],
			["DWORD","hBitmapChecked","in"],
			])

		railgun.add_function( 'user32', 'SetMenuItemInfoW', 'BOOL',[
			["DWORD","hmenu","in"],
			["DWORD","item","in"],
			["BOOL","fByPositon","in"],
			["PBLOB","lpmii","in"],
			])

		railgun.add_function( 'user32', 'SetMessageExtraInfo', 'DWORD',[
			["DWORD","lParam","in"],
			])

		railgun.add_function( 'user32', 'SetMessageQueue', 'BOOL',[
			["DWORD","cMessagesMax","in"],
			])

		railgun.add_function( 'user32', 'SetParent', 'DWORD',[
			["DWORD","hWndChild","in"],
			["DWORD","hWndNewParent","in"],
			])

		railgun.add_function( 'user32', 'SetProcessDefaultLayout', 'BOOL',[
			["DWORD","dwDefaultLayout","in"],
			])

		railgun.add_function( 'user32', 'SetProcessWindowStation', 'BOOL',[
			["DWORD","hWinSta","in"],
			])

		railgun.add_function( 'user32', 'SetPropA', 'BOOL',[
			["DWORD","hWnd","in"],
			["PCHAR","lpString","in"],
			["DWORD","hData","in"],
			])

		railgun.add_function( 'user32', 'SetPropW', 'BOOL',[
			["DWORD","hWnd","in"],
			["PWCHAR","lpString","in"],
			["DWORD","hData","in"],
			])

		railgun.add_function( 'user32', 'SetRect', 'BOOL',[
			["PBLOB","lprc","out"],
			["DWORD","xLeft","in"],
			["DWORD","yTop","in"],
			["DWORD","xRight","in"],
			["DWORD","yBottom","in"],
			])

		railgun.add_function( 'user32', 'SetRectEmpty', 'BOOL',[
			["PBLOB","lprc","out"],
			])

		railgun.add_function( 'user32', 'SetScrollInfo', 'DWORD',[
			["DWORD","hwnd","in"],
			["DWORD","nBar","in"],
			["PBLOB","lpsi","in"],
			["BOOL","redraw","in"],
			])

		railgun.add_function( 'user32', 'SetScrollPos', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","nBar","in"],
			["DWORD","nPos","in"],
			["BOOL","bRedraw","in"],
			])

		railgun.add_function( 'user32', 'SetScrollRange', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","nBar","in"],
			["DWORD","nMinPos","in"],
			["DWORD","nMaxPos","in"],
			["BOOL","bRedraw","in"],
			])

		railgun.add_function( 'user32', 'SetSystemCursor', 'BOOL',[
			["DWORD","hcur","in"],
			["DWORD","id","in"],
			])

		railgun.add_function( 'user32', 'SetThreadDesktop', 'BOOL',[
			["DWORD","hDesktop","in"],
			])

		railgun.add_function( 'user32', 'SetTimer', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","nIDEvent","in"],
			["DWORD","uElapse","in"],
			["PBLOB","lpTimerFunc","in"],
			])

		railgun.add_function( 'user32', 'SetUserObjectInformationA', 'BOOL',[
			["DWORD","hObj","in"],
			["DWORD","nIndex","in"],
			["PBLOB","pvInfo","in"],
			["DWORD","nLength","in"],
			])

		railgun.add_function( 'user32', 'SetUserObjectInformationW', 'BOOL',[
			["DWORD","hObj","in"],
			["DWORD","nIndex","in"],
			["PBLOB","pvInfo","in"],
			["DWORD","nLength","in"],
			])

		railgun.add_function( 'user32', 'SetUserObjectSecurity', 'BOOL',[
			["DWORD","hObj","in"],
			["PBLOB","pSIRequested","in"],
			["PBLOB","pSID","in"],
			])

		railgun.add_function( 'user32', 'SetWindowContextHelpId', 'BOOL',[
			["DWORD","param0","in"],
			["DWORD","param1","in"],
			])

		railgun.add_function( 'user32', 'SetWindowLongA', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","nIndex","in"],
			["DWORD","dwNewLong","in"],
			])

		railgun.add_function( 'user32', 'SetWindowLongW', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","nIndex","in"],
			["DWORD","dwNewLong","in"],
			])

		railgun.add_function( 'user32', 'SetWindowPlacement', 'BOOL',[
			["DWORD","hWnd","in"],
			["PBLOB","lpwndpl","in"],
			])

		railgun.add_function( 'user32', 'SetWindowPos', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","hWndInsertAfter","in"],
			["DWORD","X","in"],
			["DWORD","Y","in"],
			["DWORD","cx","in"],
			["DWORD","cy","in"],
			["DWORD","uFlags","in"],
			])

		railgun.add_function( 'user32', 'SetWindowRgn', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","hRgn","in"],
			["BOOL","bRedraw","in"],
			])

		railgun.add_function( 'user32', 'SetWindowTextA', 'BOOL',[
			["DWORD","hWnd","in"],
			["PCHAR","lpString","in"],
			])

		railgun.add_function( 'user32', 'SetWindowTextW', 'BOOL',[
			["DWORD","hWnd","in"],
			["PWCHAR","lpString","in"],
			])

		railgun.add_function( 'user32', 'SetWindowWord', 'WORD',[
			["DWORD","hWnd","in"],
			["DWORD","nIndex","in"],
			["WORD","wNewWord","in"],
			])

		railgun.add_function( 'user32', 'SetWindowsHookA', 'DWORD',[
			["DWORD","nFilterType","in"],
			["DWORD","pfnFilterProc","in"],
			])

		railgun.add_function( 'user32', 'SetWindowsHookExA', 'DWORD',[
			["DWORD","idHook","in"],
			["DWORD","lpfn","in"],
			["DWORD","hmod","in"],
			["DWORD","dwThreadId","in"],
			])

		railgun.add_function( 'user32', 'SetWindowsHookExW', 'DWORD',[
			["DWORD","idHook","in"],
			["DWORD","lpfn","in"],
			["DWORD","hmod","in"],
			["DWORD","dwThreadId","in"],
			])

		railgun.add_function( 'user32', 'SetWindowsHookW', 'DWORD',[
			["DWORD","nFilterType","in"],
			["DWORD","pfnFilterProc","in"],
			])

		railgun.add_function( 'user32', 'ShowCaret', 'BOOL',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'ShowCursor', 'DWORD',[
			["BOOL","bShow","in"],
			])

		railgun.add_function( 'user32', 'ShowOwnedPopups', 'BOOL',[
			["DWORD","hWnd","in"],
			["BOOL","fShow","in"],
			])

		railgun.add_function( 'user32', 'ShowScrollBar', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","wBar","in"],
			["BOOL","bShow","in"],
			])

		railgun.add_function( 'user32', 'ShowWindow', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","nCmdShow","in"],
			])

		railgun.add_function( 'user32', 'ShowWindowAsync', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","nCmdShow","in"],
			])

		railgun.add_function( 'user32', 'SubtractRect', 'BOOL',[
			["PBLOB","lprcDst","out"],
			["PBLOB","lprcSrc1","in"],
			["PBLOB","lprcSrc2","in"],
			])

		railgun.add_function( 'user32', 'SwapMouseButton', 'BOOL',[
			["BOOL","fSwap","in"],
			])

		railgun.add_function( 'user32', 'SwitchDesktop', 'BOOL',[
			["DWORD","hDesktop","in"],
			])

		railgun.add_function( 'user32', 'SwitchToThisWindow', 'VOID',[
			["DWORD","hwnd","in"],
			["BOOL","fUnknown","in"],
			])

		railgun.add_function( 'user32', 'SystemParametersInfoA', 'BOOL',[
			["DWORD","uiAction","in"],
			["DWORD","uiParam","in"],
			["PBLOB","pvParam","inout"],
			["DWORD","fWinIni","in"],
			])

		railgun.add_function( 'user32', 'SystemParametersInfoW', 'BOOL',[
			["DWORD","uiAction","in"],
			["DWORD","uiParam","in"],
			["PBLOB","pvParam","inout"],
			["DWORD","fWinIni","in"],
			])

		railgun.add_function( 'user32', 'TabbedTextOutA', 'DWORD',[
			["DWORD","hdc","in"],
			["DWORD","x","in"],
			["DWORD","y","in"],
			["PCHAR","lpString","in"],
			["DWORD","chCount","in"],
			["DWORD","nTabPositions","in"],
			["PDWORD","lpnTabStopPositions","in"],
			["DWORD","nTabOrigin","in"],
			])

		railgun.add_function( 'user32', 'TabbedTextOutW', 'DWORD',[
			["DWORD","hdc","in"],
			["DWORD","x","in"],
			["DWORD","y","in"],
			["PWCHAR","lpString","in"],
			["DWORD","chCount","in"],
			["DWORD","nTabPositions","in"],
			["PDWORD","lpnTabStopPositions","in"],
			["DWORD","nTabOrigin","in"],
			])

		railgun.add_function( 'user32', 'TileWindows', 'WORD',[
			["DWORD","hwndParent","in"],
			["DWORD","wHow","in"],
			["PBLOB","lpRect","in"],
			["DWORD","cKids","in"],
			["PDWORD","lpKids","in"],
			])

		railgun.add_function( 'user32', 'ToAscii', 'DWORD',[
			["DWORD","uVirtKey","in"],
			["DWORD","uScanCode","in"],
			["PBLOB","lpKeyState","in"],
			["PBLOB","lpChar","out"],
			["DWORD","uFlags","in"],
			])

		railgun.add_function( 'user32', 'ToAsciiEx', 'DWORD',[
			["DWORD","uVirtKey","in"],
			["DWORD","uScanCode","in"],
			["PBLOB","lpKeyState","in"],
			["PBLOB","lpChar","out"],
			["DWORD","uFlags","in"],
			["DWORD","dwhkl","in"],
			])

		railgun.add_function( 'user32', 'TrackMouseEvent', 'BOOL',[
			["PBLOB","lpEventTrack","inout"],
			])

		railgun.add_function( 'user32', 'TrackPopupMenu', 'BOOL',[
			["DWORD","hMenu","in"],
			["DWORD","uFlags","in"],
			["DWORD","x","in"],
			["DWORD","y","in"],
			["DWORD","nReserved","in"],
			["DWORD","hWnd","in"],
			["PBLOB","prcRect","in"],
			])

		railgun.add_function( 'user32', 'TranslateAcceleratorA', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","hAccTable","in"],
			["PBLOB","lpMsg","in"],
			])

		railgun.add_function( 'user32', 'TranslateAcceleratorW', 'DWORD',[
			["DWORD","hWnd","in"],
			["DWORD","hAccTable","in"],
			["PBLOB","lpMsg","in"],
			])

		railgun.add_function( 'user32', 'TranslateMDISysAccel', 'BOOL',[
			["DWORD","hWndClient","in"],
			["PBLOB","lpMsg","in"],
			])

		railgun.add_function( 'user32', 'TranslateMessage', 'BOOL',[
			["PBLOB","lpMsg","in"],
			])

		railgun.add_function( 'user32', 'UnhookWinEvent', 'BOOL',[
			["DWORD","hWinEventHook","in"],
			])

		railgun.add_function( 'user32', 'UnhookWindowsHook', 'BOOL',[
			["DWORD","nCode","in"],
			["DWORD","pfnFilterProc","in"],
			])

		railgun.add_function( 'user32', 'UnhookWindowsHookEx', 'BOOL',[
			["DWORD","hhk","in"],
			])

		railgun.add_function( 'user32', 'UnionRect', 'BOOL',[
			["PBLOB","lprcDst","out"],
			["PBLOB","lprcSrc1","in"],
			["PBLOB","lprcSrc2","in"],
			])

		railgun.add_function( 'user32', 'UnloadKeyboardLayout', 'BOOL',[
			["DWORD","hkl","in"],
			])

		railgun.add_function( 'user32', 'UnregisterClassA', 'BOOL',[
			["PCHAR","lpClassName","in"],
			["DWORD","hInstance","in"],
			])

		railgun.add_function( 'user32', 'UnregisterClassW', 'BOOL',[
			["PWCHAR","lpClassName","in"],
			["DWORD","hInstance","in"],
			])

		railgun.add_function( 'user32', 'UnregisterDeviceNotification', 'BOOL',[
			["DWORD","Handle","in"],
			])

		railgun.add_function( 'user32', 'UnregisterHotKey', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","id","in"],
			])

		railgun.add_function( 'user32', 'UpdateWindow', 'BOOL',[
			["DWORD","hWnd","in"],
			])

		railgun.add_function( 'user32', 'UserHandleGrantAccess', 'BOOL',[
			["DWORD","hUserHandle","in"],
			["DWORD","hJob","in"],
			["BOOL","bGrant","in"],
			])

		railgun.add_function( 'user32', 'ValidateRect', 'BOOL',[
			["DWORD","hWnd","in"],
			["PBLOB","lpRect","in"],
			])

		railgun.add_function( 'user32', 'ValidateRgn', 'BOOL',[
			["DWORD","hWnd","in"],
			["DWORD","hRgn","in"],
			])

		railgun.add_function( 'user32', 'VkKeyScanA', 'WORD',[
			["BYTE","ch","in"],
			])

		railgun.add_function( 'user32', 'VkKeyScanExA', 'WORD',[
			["BYTE","ch","in"],
			["DWORD","dwhkl","in"],
			])

		railgun.add_function( 'user32', 'VkKeyScanExW', 'WORD',[
			["WORD","ch","in"],
			["DWORD","dwhkl","in"],
			])

		railgun.add_function( 'user32', 'VkKeyScanW', 'WORD',[
			["WORD","ch","in"],
			])

		railgun.add_function( 'user32', 'WaitForInputIdle', 'DWORD',[
			["DWORD","hProcess","in"],
			["DWORD","dwMilliseconds","in"],
			])

		railgun.add_function( 'user32', 'WaitMessage', 'BOOL',[
			])

		railgun.add_function( 'user32', 'WinHelpA', 'BOOL',[
			["DWORD","hWndMain","in"],
			["PCHAR","lpszHelp","in"],
			["DWORD","uCommand","in"],
			["PDWORD","dwData","in"],
			])

		railgun.add_function( 'user32', 'WinHelpW', 'BOOL',[
			["DWORD","hWndMain","in"],
			["PWCHAR","lpszHelp","in"],
			["DWORD","uCommand","in"],
			["PDWORD","dwData","in"],
			])

		railgun.add_function( 'user32', 'WindowFromDC', 'DWORD',[
			["DWORD","hDC","in"],
			])

		railgun.add_function( 'user32', 'WindowFromPoint', 'DWORD',[
			["PBLOB","Point","in"],
			])

		railgun.add_function( 'user32', 'keybd_event', 'VOID',[
			["BYTE","bVk","in"],
			["BYTE","bScan","in"],
			["DWORD","dwFlags","in"],
			["PDWORD","dwExtraInfo","in"],
			])

		railgun.add_function( 'user32', 'mouse_event', 'VOID',[
			["DWORD","dwFlags","in"],
			["DWORD","dx","in"],
			["DWORD","dy","in"],
			["DWORD","dwData","in"],
			["PDWORD","dwExtraInfo","in"],
			])

	end
	
end

end; end; end; end; end; end; end
