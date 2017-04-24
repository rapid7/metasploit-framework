# -*- coding: binary -*-
module Rex
module Post
module Meterpreter
module Extensions
module Stdapi
module Railgun
module Def

class Def_user32

  def self.create_dll(dll_path = 'user32')
    dll = DLL.new(dll_path, ApiConstants.manager)

    dll.add_function('ActivateKeyboardLayout', 'DWORD',[
      ["DWORD","hkl","in"],
      ["DWORD","Flags","in"],
      ])

    dll.add_function('AdjustWindowRect', 'BOOL',[
      ["PBLOB","lpRect","inout"],
      ["DWORD","dwStyle","in"],
      ["BOOL","bMenu","in"],
      ])

    dll.add_function('AdjustWindowRectEx', 'BOOL',[
      ["PBLOB","lpRect","inout"],
      ["DWORD","dwStyle","in"],
      ["BOOL","bMenu","in"],
      ["DWORD","dwExStyle","in"],
      ])

    dll.add_function('AllowSetForegroundWindow', 'BOOL',[
      ["DWORD","dwProcessId","in"],
      ])

    dll.add_function('AnimateWindow', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["DWORD","dwTime","in"],
      ["DWORD","dwFlags","in"],
      ])

    dll.add_function('AnyPopup', 'BOOL',[
      ])

    dll.add_function('AppendMenuA', 'BOOL',[
      ["DWORD","hMenu","in"],
      ["DWORD","uFlags","in"],
      ["DWORD","uIDNewItem","in"],
      ["PCHAR","lpNewItem","in"],
      ])

    dll.add_function('AppendMenuW', 'BOOL',[
      ["DWORD","hMenu","in"],
      ["DWORD","uFlags","in"],
      ["DWORD","uIDNewItem","in"],
      ["PWCHAR","lpNewItem","in"],
      ])

    dll.add_function('ArrangeIconicWindows', 'DWORD',[
      ["DWORD","hWnd","in"],
      ])

    dll.add_function('AttachThreadInput', 'BOOL',[
      ["DWORD","idAttach","in"],
      ["DWORD","idAttachTo","in"],
      ["BOOL","fAttach","in"],
      ])

    dll.add_function('BeginDeferWindowPos', 'DWORD',[
      ["DWORD","nNumWindows","in"],
      ])

    dll.add_function('BeginPaint', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["PBLOB","lpPaint","out"],
      ])

    dll.add_function('BringWindowToTop', 'BOOL',[
      ["DWORD","hWnd","in"],
      ])

    dll.add_function('BroadcastSystemMessage', 'DWORD',[
      ["DWORD","flags","in"],
      ["PDWORD","lpInfo","inout"],
      ["DWORD","Msg","in"],
      ["WORD","wParam","in"],
      ["DWORD","lParam","in"],
      ])

    dll.add_function('BroadcastSystemMessageA', 'DWORD',[
      ["DWORD","flags","in"],
      ["PDWORD","lpInfo","inout"],
      ["DWORD","Msg","in"],
      ["WORD","wParam","in"],
      ["DWORD","lParam","in"],
      ])

    dll.add_function('BroadcastSystemMessageExA', 'DWORD',[
      ["DWORD","flags","in"],
      ["PDWORD","lpInfo","inout"],
      ["DWORD","Msg","in"],
      ["WORD","wParam","in"],
      ["DWORD","lParam","in"],
      ["PBLOB","pbsmInfo","out"],
      ])

    dll.add_function('BroadcastSystemMessageExW', 'DWORD',[
      ["DWORD","flags","in"],
      ["PDWORD","lpInfo","inout"],
      ["DWORD","Msg","in"],
      ["WORD","wParam","in"],
      ["DWORD","lParam","in"],
      ["PBLOB","pbsmInfo","out"],
      ])

    dll.add_function('BroadcastSystemMessageW', 'DWORD',[
      ["DWORD","flags","in"],
      ["PDWORD","lpInfo","inout"],
      ["DWORD","Msg","in"],
      ["WORD","wParam","in"],
      ["DWORD","lParam","in"],
      ])

    dll.add_function('CallMsgFilterA', 'BOOL',[
      ["PBLOB","lpMsg","in"],
      ["DWORD","nCode","in"],
      ])

    dll.add_function('CallMsgFilterW', 'BOOL',[
      ["PBLOB","lpMsg","in"],
      ["DWORD","nCode","in"],
      ])

    dll.add_function('CallNextHookEx', 'DWORD',[
      ["DWORD","hhk","in"],
      ["DWORD","nCode","in"],
      ["WORD","wParam","in"],
      ["DWORD","lParam","in"],
      ])

    dll.add_function('CallWindowProcA', 'DWORD',[
      ["PBLOB","lpPrevWndFunc","in"],
      ["DWORD","hWnd","in"],
      ["DWORD","Msg","in"],
      ["WORD","wParam","in"],
      ["DWORD","lParam","in"],
      ])

    dll.add_function('CallWindowProcW', 'DWORD',[
      ["PBLOB","lpPrevWndFunc","in"],
      ["DWORD","hWnd","in"],
      ["DWORD","Msg","in"],
      ["WORD","wParam","in"],
      ["DWORD","lParam","in"],
      ])

    dll.add_function('CascadeWindows', 'WORD',[
      ["DWORD","hwndParent","in"],
      ["DWORD","wHow","in"],
      ["PBLOB","lpRect","in"],
      ["DWORD","cKids","in"],
      ["PDWORD","lpKids","in"],
      ])

    dll.add_function('ChangeClipboardChain', 'BOOL',[
      ["DWORD","hWndRemove","in"],
      ["DWORD","hWndNewNext","in"],
      ])

    dll.add_function('ChangeDisplaySettingsA', 'DWORD',[
      ["PBLOB","lpDevMode","in"],
      ["DWORD","dwFlags","in"],
      ])

    dll.add_function('ChangeDisplaySettingsExA', 'DWORD',[
      ["PCHAR","lpszDeviceName","in"],
      ["PBLOB","lpDevMode","in"],
      ["DWORD","hwnd","inout"],
      ["DWORD","dwflags","in"],
      ["PBLOB","lParam","in"],
      ])

    dll.add_function('ChangeDisplaySettingsExW', 'DWORD',[
      ["PWCHAR","lpszDeviceName","in"],
      ["PBLOB","lpDevMode","in"],
      ["DWORD","hwnd","inout"],
      ["DWORD","dwflags","in"],
      ["PBLOB","lParam","in"],
      ])

    dll.add_function('ChangeDisplaySettingsW', 'DWORD',[
      ["PBLOB","lpDevMode","in"],
      ["DWORD","dwFlags","in"],
      ])

    dll.add_function('ChangeMenuA', 'BOOL',[
      ["DWORD","hMenu","in"],
      ["DWORD","cmd","in"],
      ["PCHAR","lpszNewItem","in"],
      ["DWORD","cmdInsert","in"],
      ["DWORD","flags","in"],
      ])

    dll.add_function('ChangeMenuW', 'BOOL',[
      ["DWORD","hMenu","in"],
      ["DWORD","cmd","in"],
      ["PWCHAR","lpszNewItem","in"],
      ["DWORD","cmdInsert","in"],
      ["DWORD","flags","in"],
      ])

    dll.add_function('CharLowerBuffA', 'DWORD',[
      ["PCHAR","lpsz","in"],
      ["DWORD","cchLength","in"],
      ])

    dll.add_function('CharLowerBuffW', 'DWORD',[
      ["PWCHAR","lpsz","in"],
      ["DWORD","cchLength","in"],
      ])

    dll.add_function('CharToOemA', 'BOOL',[
      ["PCHAR","lpszSrc","in"],
      ["PCHAR","lpszDst","out"],
      ])

    dll.add_function('CharToOemBuffA', 'BOOL',[
      ["PCHAR","lpszSrc","in"],
      ["PCHAR","lpszDst","out"],
      ["DWORD","cchDstLength","in"],
      ])

    dll.add_function('CharToOemBuffW', 'BOOL',[
      ["PWCHAR","lpszSrc","in"],
      ["PCHAR","lpszDst","out"],
      ["DWORD","cchDstLength","in"],
      ])

    dll.add_function('CharToOemW', 'BOOL',[
      ["PWCHAR","lpszSrc","in"],
      ["PCHAR","lpszDst","out"],
      ])

    dll.add_function('CharUpperBuffA', 'DWORD',[
      ["PCHAR","lpsz","in"],
      ["DWORD","cchLength","in"],
      ])

    dll.add_function('CharUpperBuffW', 'DWORD',[
      ["PWCHAR","lpsz","in"],
      ["DWORD","cchLength","in"],
      ])

    dll.add_function('CheckDlgButton', 'BOOL',[
      ["DWORD","hDlg","in"],
      ["DWORD","nIDButton","in"],
      ["DWORD","uCheck","in"],
      ])

    dll.add_function('CheckMenuItem', 'DWORD',[
      ["DWORD","hMenu","in"],
      ["DWORD","uIDCheckItem","in"],
      ["DWORD","uCheck","in"],
      ])

    dll.add_function('CheckMenuRadioItem', 'BOOL',[
      ["DWORD","hmenu","in"],
      ["DWORD","first","in"],
      ["DWORD","last","in"],
      ["DWORD","check","in"],
      ["DWORD","flags","in"],
      ])

    dll.add_function('CheckRadioButton', 'BOOL',[
      ["DWORD","hDlg","in"],
      ["DWORD","nIDFirstButton","in"],
      ["DWORD","nIDLastButton","in"],
      ["DWORD","nIDCheckButton","in"],
      ])

    dll.add_function('ChildWindowFromPoint', 'DWORD',[
      ["DWORD","hWndParent","in"],
      ["PBLOB","Point","in"],
      ])

    dll.add_function('ChildWindowFromPointEx', 'DWORD',[
      ["DWORD","hwnd","in"],
      ["PBLOB","pt","in"],
      ["DWORD","flags","in"],
      ])

    dll.add_function('ClientToScreen', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["PBLOB","lpPoint","inout"],
      ])

    dll.add_function('ClipCursor', 'BOOL',[
      ["PBLOB","lpRect","in"],
      ])

    dll.add_function('CloseClipboard', 'BOOL',[
      ])

    dll.add_function('CloseDesktop', 'BOOL',[
      ["DWORD","hDesktop","in"],
      ])

    dll.add_function('CloseWindow', 'BOOL',[
      ["DWORD","hWnd","in"],
      ])

    dll.add_function('CloseWindowStation', 'BOOL',[
      ["DWORD","hWinSta","in"],
      ])

    dll.add_function('CopyAcceleratorTableA', 'DWORD',[
      ["DWORD","hAccelSrc","in"],
      ["PBLOB","lpAccelDst","out"],
      ["DWORD","cAccelEntries","in"],
      ])

    dll.add_function('CopyAcceleratorTableW', 'DWORD',[
      ["DWORD","hAccelSrc","in"],
      ["PBLOB","lpAccelDst","out"],
      ["DWORD","cAccelEntries","in"],
      ])

    dll.add_function('CopyIcon', 'DWORD',[
      ["DWORD","hIcon","in"],
      ])

    dll.add_function('CopyImage', 'DWORD',[
      ["DWORD","h","in"],
      ["DWORD","type","in"],
      ["DWORD","cx","in"],
      ["DWORD","cy","in"],
      ["DWORD","flags","in"],
      ])

    dll.add_function('CopyRect', 'BOOL',[
      ["PBLOB","lprcDst","out"],
      ["PBLOB","lprcSrc","in"],
      ])

    dll.add_function('CountClipboardFormats', 'DWORD',[
      ])

    dll.add_function('CreateAcceleratorTableA', 'DWORD',[
      ["PBLOB","paccel","in"],
      ["DWORD","cAccel","in"],
      ])

    dll.add_function('CreateAcceleratorTableW', 'DWORD',[
      ["PBLOB","paccel","in"],
      ["DWORD","cAccel","in"],
      ])

    dll.add_function('CreateCaret', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["DWORD","hBitmap","in"],
      ["DWORD","nWidth","in"],
      ["DWORD","nHeight","in"],
      ])

    dll.add_function('CreateCursor', 'DWORD',[
      ["DWORD","hInst","in"],
      ["DWORD","xHotSpot","in"],
      ["DWORD","yHotSpot","in"],
      ["DWORD","nWidth","in"],
      ["DWORD","nHeight","in"],
      ])

    dll.add_function('CreateDesktopA', 'DWORD',[
      ["PCHAR","lpszDesktop","in"],
      ["PCHAR","lpszDevice","inout"],
      ["PBLOB","pDevmode","inout"],
      ["DWORD","dwFlags","in"],
      ["DWORD","dwDesiredAccess","in"],
      ["PBLOB","lpsa","in"],
      ])

    dll.add_function('CreateDesktopW', 'DWORD',[
      ["PWCHAR","lpszDesktop","in"],
      ["PWCHAR","lpszDevice","inout"],
      ["PBLOB","pDevmode","inout"],
      ["DWORD","dwFlags","in"],
      ["DWORD","dwDesiredAccess","in"],
      ["PBLOB","lpsa","in"],
      ])

    dll.add_function('CreateDialogIndirectParamA', 'DWORD',[
      ["DWORD","hInstance","in"],
      ["PBLOB","lpTemplate","in"],
      ["DWORD","hWndParent","in"],
      ["PBLOB","lpDialogFunc","in"],
      ["DWORD","dwInitParam","in"],
      ])

    dll.add_function('CreateDialogIndirectParamW', 'DWORD',[
      ["DWORD","hInstance","in"],
      ["PBLOB","lpTemplate","in"],
      ["DWORD","hWndParent","in"],
      ["PBLOB","lpDialogFunc","in"],
      ["DWORD","dwInitParam","in"],
      ])

    dll.add_function('CreateDialogParamA', 'DWORD',[
      ["DWORD","hInstance","in"],
      ["PCHAR","lpTemplateName","in"],
      ["DWORD","hWndParent","in"],
      ["PBLOB","lpDialogFunc","in"],
      ["DWORD","dwInitParam","in"],
      ])

    dll.add_function('CreateDialogParamW', 'DWORD',[
      ["DWORD","hInstance","in"],
      ["PWCHAR","lpTemplateName","in"],
      ["DWORD","hWndParent","in"],
      ["PBLOB","lpDialogFunc","in"],
      ["DWORD","dwInitParam","in"],
      ])

    dll.add_function('CreateIcon', 'DWORD',[
      ["DWORD","hInstance","in"],
      ["DWORD","nWidth","in"],
      ["DWORD","nHeight","in"],
      ["BYTE","cPlanes","in"],
      ["BYTE","cBitsPixel","in"],
      ["PBLOB","lpbANDbits","in"],
      ["PBLOB","lpbXORbits","in"],
      ])

    dll.add_function('CreateIconFromResource', 'DWORD',[
      ["PBLOB","presbits","in"],
      ["DWORD","dwResSize","in"],
      ["BOOL","fIcon","in"],
      ["DWORD","dwVer","in"],
      ])

    dll.add_function('CreateIconFromResourceEx', 'DWORD',[
      ["PBLOB","presbits","in"],
      ["DWORD","dwResSize","in"],
      ["BOOL","fIcon","in"],
      ["DWORD","dwVer","in"],
      ["DWORD","cxDesired","in"],
      ["DWORD","cyDesired","in"],
      ["DWORD","Flags","in"],
      ])

    dll.add_function('CreateIconIndirect', 'DWORD',[
      ["PBLOB","piconinfo","in"],
      ])

    dll.add_function('CreateMDIWindowA', 'DWORD',[
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

    dll.add_function('CreateMDIWindowW', 'DWORD',[
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

    dll.add_function('CreateMenu', 'DWORD',[
      ])

    dll.add_function('CreatePopupMenu', 'DWORD',[
      ])

    dll.add_function('CreateWindowExA', 'DWORD',[
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

    dll.add_function('CreateWindowExW', 'DWORD',[
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

    dll.add_function('CreateWindowStationA', 'DWORD',[
      ["PCHAR","lpwinsta","in"],
      ["DWORD","dwFlags","in"],
      ["DWORD","dwDesiredAccess","in"],
      ["PBLOB","lpsa","in"],
      ])

    dll.add_function('CreateWindowStationW', 'DWORD',[
      ["PWCHAR","lpwinsta","in"],
      ["DWORD","dwFlags","in"],
      ["DWORD","dwDesiredAccess","in"],
      ["PBLOB","lpsa","in"],
      ])

    dll.add_function('DefDlgProcA', 'DWORD',[
      ["DWORD","hDlg","in"],
      ["DWORD","Msg","in"],
      ["WORD","wParam","in"],
      ["DWORD","lParam","in"],
      ])

    dll.add_function('DefDlgProcW', 'DWORD',[
      ["DWORD","hDlg","in"],
      ["DWORD","Msg","in"],
      ["WORD","wParam","in"],
      ["DWORD","lParam","in"],
      ])

    dll.add_function('DefFrameProcA', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","hWndMDIClient","in"],
      ["DWORD","uMsg","in"],
      ["WORD","wParam","in"],
      ["DWORD","lParam","in"],
      ])

    dll.add_function('DefFrameProcW', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","hWndMDIClient","in"],
      ["DWORD","uMsg","in"],
      ["WORD","wParam","in"],
      ["DWORD","lParam","in"],
      ])

    dll.add_function('DefMDIChildProcA', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","uMsg","in"],
      ["WORD","wParam","in"],
      ["DWORD","lParam","in"],
      ])

    dll.add_function('DefMDIChildProcW', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","uMsg","in"],
      ["WORD","wParam","in"],
      ["DWORD","lParam","in"],
      ])

    dll.add_function('DefRawInputProc', 'DWORD',[
      ["PBLOB","paRawInput","in"],
      ["DWORD","nInput","in"],
      ["DWORD","cbSizeHeader","in"],
      ])

    dll.add_function('DefWindowProcA', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","Msg","in"],
      ["WORD","wParam","in"],
      ["DWORD","lParam","in"],
      ])

    dll.add_function('DefWindowProcW', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","Msg","in"],
      ["WORD","wParam","in"],
      ["DWORD","lParam","in"],
      ])

    dll.add_function('DeferWindowPos', 'DWORD',[
      ["DWORD","hWinPosInfo","in"],
      ["DWORD","hWnd","in"],
      ["DWORD","hWndInsertAfter","in"],
      ["DWORD","x","in"],
      ["DWORD","y","in"],
      ["DWORD","cx","in"],
      ["DWORD","cy","in"],
      ["DWORD","uFlags","in"],
      ])

    dll.add_function('DeleteMenu', 'BOOL',[
      ["DWORD","hMenu","in"],
      ["DWORD","uPosition","in"],
      ["DWORD","uFlags","in"],
      ])

    dll.add_function('DeregisterShellHookWindow', 'BOOL',[
      ["DWORD","hwnd","in"],
      ])

    dll.add_function('DestroyAcceleratorTable', 'BOOL',[
      ["DWORD","hAccel","in"],
      ])

    dll.add_function('DestroyCaret', 'BOOL',[
      ])

    dll.add_function('DestroyCursor', 'BOOL',[
      ["DWORD","hCursor","in"],
      ])

    dll.add_function('DestroyIcon', 'BOOL',[
      ["DWORD","hIcon","in"],
      ])

    dll.add_function('DestroyMenu', 'BOOL',[
      ["DWORD","hMenu","in"],
      ])

    dll.add_function('DestroyWindow', 'BOOL',[
      ["DWORD","hWnd","in"],
      ])

    dll.add_function('DisableProcessWindowsGhosting', 'VOID',[
      ])

    dll.add_function('DispatchMessageA', 'DWORD',[
      ["PBLOB","lpMsg","in"],
      ])

    dll.add_function('DispatchMessageW', 'DWORD',[
      ["PBLOB","lpMsg","in"],
      ])

    dll.add_function('DlgDirListA', 'DWORD',[
      ["DWORD","hDlg","in"],
      ["PCHAR","lpPathSpec","inout"],
      ["DWORD","nIDListBox","in"],
      ["DWORD","nIDStaticPath","in"],
      ["DWORD","uFileType","in"],
      ])

    dll.add_function('DlgDirListComboBoxA', 'DWORD',[
      ["DWORD","hDlg","in"],
      ["PCHAR","lpPathSpec","inout"],
      ["DWORD","nIDComboBox","in"],
      ["DWORD","nIDStaticPath","in"],
      ["DWORD","uFiletype","in"],
      ])

    dll.add_function('DlgDirListComboBoxW', 'DWORD',[
      ["DWORD","hDlg","in"],
      ["PWCHAR","lpPathSpec","inout"],
      ["DWORD","nIDComboBox","in"],
      ["DWORD","nIDStaticPath","in"],
      ["DWORD","uFiletype","in"],
      ])

    dll.add_function('DlgDirListW', 'DWORD',[
      ["DWORD","hDlg","in"],
      ["PWCHAR","lpPathSpec","inout"],
      ["DWORD","nIDListBox","in"],
      ["DWORD","nIDStaticPath","in"],
      ["DWORD","uFileType","in"],
      ])

    dll.add_function('DlgDirSelectComboBoxExA', 'BOOL',[
      ["DWORD","hwndDlg","in"],
      ["PCHAR","lpString","out"],
      ["DWORD","cchOut","in"],
      ["DWORD","idComboBox","in"],
      ])

    dll.add_function('DlgDirSelectComboBoxExW', 'BOOL',[
      ["DWORD","hwndDlg","in"],
      ["PWCHAR","lpString","out"],
      ["DWORD","cchOut","in"],
      ["DWORD","idComboBox","in"],
      ])

    dll.add_function('DlgDirSelectExA', 'BOOL',[
      ["DWORD","hwndDlg","in"],
      ["PCHAR","lpString","out"],
      ["DWORD","chCount","in"],
      ["DWORD","idListBox","in"],
      ])

    dll.add_function('DlgDirSelectExW', 'BOOL',[
      ["DWORD","hwndDlg","in"],
      ["PWCHAR","lpString","out"],
      ["DWORD","chCount","in"],
      ["DWORD","idListBox","in"],
      ])

    dll.add_function('DragDetect', 'BOOL',[
      ["DWORD","hwnd","in"],
      ["PBLOB","pt","in"],
      ])

    dll.add_function('DragObject', 'DWORD',[
      ["DWORD","hwndParent","in"],
      ["DWORD","hwndFrom","in"],
      ["DWORD","fmt","in"],
      ["PDWORD","data","in"],
      ["DWORD","hcur","in"],
      ])

    dll.add_function('DrawAnimatedRects', 'BOOL',[
      ["DWORD","hwnd","in"],
      ["DWORD","idAni","in"],
      ["PBLOB","lprcFrom","in"],
      ["PBLOB","lprcTo","in"],
      ])

    dll.add_function('DrawCaption', 'BOOL',[
      ["DWORD","hwnd","in"],
      ["DWORD","hdc","in"],
      ["PBLOB","lprect","in"],
      ["DWORD","flags","in"],
      ])

    dll.add_function('DrawEdge', 'BOOL',[
      ["DWORD","hdc","in"],
      ["PBLOB","qrc","inout"],
      ["DWORD","edge","in"],
      ["DWORD","grfFlags","in"],
      ])

    dll.add_function('DrawFocusRect', 'BOOL',[
      ["DWORD","hDC","in"],
      ["PBLOB","lprc","in"],
      ])

    dll.add_function('DrawIcon', 'BOOL',[
      ["DWORD","hDC","in"],
      ["DWORD","X","in"],
      ["DWORD","Y","in"],
      ["DWORD","hIcon","in"],
      ])

    dll.add_function('DrawIconEx', 'BOOL',[
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

    dll.add_function('DrawMenuBar', 'BOOL',[
      ["DWORD","hWnd","in"],
      ])

    dll.add_function('DrawStateA', 'BOOL',[
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

    dll.add_function('DrawStateW', 'BOOL',[
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

    dll.add_function('DrawTextA', 'DWORD',[
      ["DWORD","hdc","in"],
      ["PCHAR","lpchText","in"],
      ["DWORD","cchText","in"],
      ["PBLOB","lprc","inout"],
      ["DWORD","format","in"],
      ])

    dll.add_function('DrawTextExA', 'DWORD',[
      ["DWORD","hdc","in"],
      ["PCHAR","lpchText","in"],
      ["DWORD","cchText","in"],
      ["PBLOB","lprc","inout"],
      ["DWORD","format","in"],
      ["PBLOB","lpdtp","in"],
      ])

    dll.add_function('DrawTextExW', 'DWORD',[
      ["DWORD","hdc","in"],
      ["PWCHAR","lpchText","in"],
      ["DWORD","cchText","in"],
      ["PBLOB","lprc","inout"],
      ["DWORD","format","in"],
      ["PBLOB","lpdtp","in"],
      ])

    dll.add_function('DrawTextW', 'DWORD',[
      ["DWORD","hdc","in"],
      ["PWCHAR","lpchText","in"],
      ["DWORD","cchText","in"],
      ["PBLOB","lprc","inout"],
      ["DWORD","format","in"],
      ])

    dll.add_function('EmptyClipboard', 'BOOL',[
      ])

    dll.add_function('EnableMenuItem', 'BOOL',[
      ["DWORD","hMenu","in"],
      ["DWORD","uIDEnableItem","in"],
      ["DWORD","uEnable","in"],
      ])

    dll.add_function('EnableScrollBar', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["DWORD","wSBflags","in"],
      ["DWORD","wArrows","in"],
      ])

    dll.add_function('EnableWindow', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["BOOL","bEnable","in"],
      ])

    dll.add_function('EndDeferWindowPos', 'BOOL',[
      ["DWORD","hWinPosInfo","in"],
      ])

    dll.add_function('EndDialog', 'BOOL',[
      ["DWORD","hDlg","in"],
      ["PDWORD","nResult","in"],
      ])

    dll.add_function('EndMenu', 'BOOL',[
      ])

    dll.add_function('EndPaint', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["PBLOB","lpPaint","in"],
      ])

    dll.add_function('EndTask', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["BOOL","fShutDown","in"],
      ["BOOL","fForce","in"],
      ])

    dll.add_function('EnumChildWindows', 'BOOL',[
      ["DWORD","hWndParent","in"],
      ["PBLOB","lpEnumFunc","in"],
      ["DWORD","lParam","in"],
      ])

    dll.add_function('EnumClipboardFormats', 'DWORD',[
      ["DWORD","format","in"],
      ])

    dll.add_function('EnumDesktopWindows', 'BOOL',[
      ["DWORD","hDesktop","in"],
      ["PBLOB","lpfn","in"],
      ["DWORD","lParam","in"],
      ])

    dll.add_function('EnumDesktopsA', 'BOOL',[
      ["DWORD","hwinsta","in"],
      ["PBLOB","lpEnumFunc","in"],
      ["DWORD","lParam","in"],
      ])

    dll.add_function('EnumDesktopsW', 'BOOL',[
      ["DWORD","hwinsta","in"],
      ["PBLOB","lpEnumFunc","in"],
      ["DWORD","lParam","in"],
      ])

    dll.add_function('EnumDisplayDevicesA', 'BOOL',[
      ["PCHAR","lpDevice","in"],
      ["DWORD","iDevNum","in"],
      ["PBLOB","lpDisplayDevice","inout"],
      ["DWORD","dwFlags","in"],
      ])

    dll.add_function('EnumDisplayDevicesW', 'BOOL',[
      ["PWCHAR","lpDevice","in"],
      ["DWORD","iDevNum","in"],
      ["PBLOB","lpDisplayDevice","inout"],
      ["DWORD","dwFlags","in"],
      ])

    dll.add_function('EnumDisplayMonitors', 'BOOL',[
      ["DWORD","hdc","in"],
      ["PBLOB","lprcClip","in"],
      ["PBLOB","lpfnEnum","in"],
      ["DWORD","dwData","in"],
      ])

    dll.add_function('EnumDisplaySettingsA', 'BOOL',[
      ["PCHAR","lpszDeviceName","in"],
      ["DWORD","iModeNum","in"],
      ["PBLOB","lpDevMode","out"],
      ])

    dll.add_function('EnumDisplaySettingsExA', 'BOOL',[
      ["PCHAR","lpszDeviceName","in"],
      ["DWORD","iModeNum","in"],
      ["PBLOB","lpDevMode","out"],
      ["DWORD","dwFlags","in"],
      ])

    dll.add_function('EnumDisplaySettingsExW', 'BOOL',[
      ["PWCHAR","lpszDeviceName","in"],
      ["DWORD","iModeNum","in"],
      ["PBLOB","lpDevMode","out"],
      ["DWORD","dwFlags","in"],
      ])

    dll.add_function('EnumDisplaySettingsW', 'BOOL',[
      ["PWCHAR","lpszDeviceName","in"],
      ["DWORD","iModeNum","in"],
      ["PBLOB","lpDevMode","out"],
      ])

    dll.add_function('EnumPropsA', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["PBLOB","lpEnumFunc","in"],
      ])

    dll.add_function('EnumPropsExA', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["PBLOB","lpEnumFunc","in"],
      ["DWORD","lParam","in"],
      ])

    dll.add_function('EnumPropsExW', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["PBLOB","lpEnumFunc","in"],
      ["DWORD","lParam","in"],
      ])

    dll.add_function('EnumPropsW', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["PBLOB","lpEnumFunc","in"],
      ])

    dll.add_function('EnumThreadWindows', 'BOOL',[
      ["DWORD","dwThreadId","in"],
      ["PBLOB","lpfn","in"],
      ["DWORD","lParam","in"],
      ])

    dll.add_function('EnumWindowStationsA', 'BOOL',[
      ["PBLOB","lpEnumFunc","in"],
      ["DWORD","lParam","in"],
      ])

    dll.add_function('EnumWindowStationsW', 'BOOL',[
      ["PBLOB","lpEnumFunc","in"],
      ["DWORD","lParam","in"],
      ])

    dll.add_function('EnumWindows', 'BOOL',[
      ["PBLOB","lpEnumFunc","in"],
      ["DWORD","lParam","in"],
      ])

    dll.add_function('EqualRect', 'BOOL',[
      ["PBLOB","lprc1","in"],
      ["PBLOB","lprc2","in"],
      ])

    dll.add_function('ExcludeUpdateRgn', 'DWORD',[
      ["DWORD","hDC","in"],
      ["DWORD","hWnd","in"],
      ])

    dll.add_function('ExitWindowsEx', 'BOOL',[
      ["DWORD","uFlags","in"],
      ["DWORD","dwReason","in"],
      ])

    dll.add_function('FillRect', 'DWORD',[
      ["DWORD","hDC","in"],
      ["PBLOB","lprc","in"],
      ["DWORD","hbr","in"],
      ])

    dll.add_function('FindWindowA', 'DWORD',[
      ["PCHAR","lpClassName","in"],
      ["PCHAR","lpWindowName","in"],
      ])

    dll.add_function('FindWindowExA', 'DWORD',[
      ["DWORD","hWndParent","in"],
      ["DWORD","hWndChildAfter","in"],
      ["PCHAR","lpszClass","in"],
      ["PCHAR","lpszWindow","in"],
      ])

    dll.add_function('FindWindowExW', 'DWORD',[
      ["DWORD","hWndParent","in"],
      ["DWORD","hWndChildAfter","in"],
      ["PWCHAR","lpszClass","in"],
      ["PWCHAR","lpszWindow","in"],
      ])

    dll.add_function('FindWindowW', 'DWORD',[
      ["PWCHAR","lpClassName","in"],
      ["PWCHAR","lpWindowName","in"],
      ])

    dll.add_function('FlashWindow', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["BOOL","bInvert","in"],
      ])

    dll.add_function('FlashWindowEx', 'BOOL',[
      ["PBLOB","pfwi","in"],
      ])

    dll.add_function('FrameRect', 'DWORD',[
      ["DWORD","hDC","in"],
      ["PBLOB","lprc","in"],
      ["DWORD","hbr","in"],
      ])

    dll.add_function('GetActiveWindow', 'DWORD',[
      ])

    dll.add_function('GetAltTabInfoA', 'BOOL',[
      ["DWORD","hwnd","in"],
      ["DWORD","iItem","in"],
      ["PBLOB","pati","inout"],
      ["PCHAR","pszItemText","out"],
      ["DWORD","cchItemText","in"],
      ])

    dll.add_function('GetAltTabInfoW', 'BOOL',[
      ["DWORD","hwnd","in"],
      ["DWORD","iItem","in"],
      ["PBLOB","pati","inout"],
      ["PWCHAR","pszItemText","out"],
      ["DWORD","cchItemText","in"],
      ])

    dll.add_function('GetAncestor', 'DWORD',[
      ["DWORD","hwnd","in"],
      ["DWORD","gaFlags","in"],
      ])

    dll.add_function('GetAsyncKeyState', 'WORD',[
      ["DWORD","vKey","in"],
      ])

    dll.add_function('GetCapture', 'DWORD',[
      ])

    dll.add_function('GetCaretBlinkTime', 'DWORD',[
      ])

    dll.add_function('GetCaretPos', 'BOOL',[
      ["PBLOB","lpPoint","out"],
      ])

    dll.add_function('GetClassInfoA', 'BOOL',[
      ["DWORD","hInstance","in"],
      ["PCHAR","lpClassName","in"],
      ["PBLOB","lpWndClass","out"],
      ])

    dll.add_function('GetClassInfoExA', 'BOOL',[
      ["DWORD","hInstance","in"],
      ["PCHAR","lpszClass","in"],
      ["PBLOB","lpwcx","out"],
      ])

    dll.add_function('GetClassInfoExW', 'BOOL',[
      ["DWORD","hInstance","in"],
      ["PWCHAR","lpszClass","in"],
      ["PBLOB","lpwcx","out"],
      ])

    dll.add_function('GetClassInfoW', 'BOOL',[
      ["DWORD","hInstance","in"],
      ["PWCHAR","lpClassName","in"],
      ["PBLOB","lpWndClass","out"],
      ])

    dll.add_function('GetClassLongA', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","nIndex","in"],
      ])

    dll.add_function('GetClassLongW', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","nIndex","in"],
      ])

    dll.add_function('GetClassNameA', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["PCHAR","lpClassName","out"],
      ["DWORD","nMaxCount","in"],
      ])

    dll.add_function('GetClassNameW', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["PWCHAR","lpClassName","out"],
      ["DWORD","nMaxCount","in"],
      ])

    dll.add_function('GetClassWord', 'WORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","nIndex","in"],
      ])

    dll.add_function('GetClientRect', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["PBLOB","lpRect","out"],
      ])

    dll.add_function('GetClipCursor', 'BOOL',[
      ["PBLOB","lpRect","out"],
      ])

    dll.add_function('GetClipboardData', 'DWORD',[
      ["DWORD","uFormat","in"],
      ])

    dll.add_function('GetClipboardFormatNameA', 'DWORD',[
      ["DWORD","format","in"],
      ["PCHAR","lpszFormatName","out"],
      ["DWORD","cchMaxCount","in"],
      ])

    dll.add_function('GetClipboardFormatNameW', 'DWORD',[
      ["DWORD","format","in"],
      ["PWCHAR","lpszFormatName","out"],
      ["DWORD","cchMaxCount","in"],
      ])

    dll.add_function('GetClipboardOwner', 'DWORD',[
      ])

    dll.add_function('GetClipboardSequenceNumber', 'DWORD',[
      ])

    dll.add_function('GetClipboardViewer', 'DWORD',[
      ])

    dll.add_function('GetComboBoxInfo', 'BOOL',[
      ["DWORD","hwndCombo","in"],
      ["PBLOB","pcbi","inout"],
      ])

    dll.add_function('GetCursor', 'DWORD',[
      ])

    dll.add_function('GetCursorInfo', 'BOOL',[
      ["PBLOB","pci","inout"],
      ])

    dll.add_function('GetCursorPos', 'BOOL',[
      ["PBLOB","lpPoint","out"],
      ])

    dll.add_function('GetDC', 'DWORD',[
      ["DWORD","hWnd","in"],
      ])

    dll.add_function('GetDCEx', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","hrgnClip","in"],
      ["DWORD","flags","in"],
      ])

    dll.add_function('GetDesktopWindow', 'DWORD',[
      ])

    dll.add_function('GetDialogBaseUnits', 'DWORD',[
      ])

    dll.add_function('GetDlgCtrlID', 'DWORD',[
      ["DWORD","hWnd","in"],
      ])

    dll.add_function('GetDlgItem', 'DWORD',[
      ["DWORD","hDlg","in"],
      ["DWORD","nIDDlgItem","in"],
      ])

    dll.add_function('GetDlgItemInt', 'DWORD',[
      ["DWORD","hDlg","in"],
      ["DWORD","nIDDlgItem","in"],
      ["PBLOB","lpTranslated","out"],
      ["BOOL","bSigned","in"],
      ])

    dll.add_function('GetDlgItemTextA', 'DWORD',[
      ["DWORD","hDlg","in"],
      ["DWORD","nIDDlgItem","in"],
      ["PCHAR","lpString","out"],
      ["DWORD","cchMax","in"],
      ])

    dll.add_function('GetDlgItemTextW', 'DWORD',[
      ["DWORD","hDlg","in"],
      ["DWORD","nIDDlgItem","in"],
      ["PWCHAR","lpString","out"],
      ["DWORD","cchMax","in"],
      ])

    dll.add_function('GetDoubleClickTime', 'DWORD',[
      ])

    dll.add_function('GetFocus', 'DWORD',[
      ])

    dll.add_function('GetForegroundWindow', 'DWORD',[
      ])

    dll.add_function('GetGUIThreadInfo', 'BOOL',[
      ["DWORD","idThread","in"],
      ["PBLOB","pgui","inout"],
      ])

    dll.add_function('GetGuiResources', 'DWORD',[
      ["DWORD","hProcess","in"],
      ["DWORD","uiFlags","in"],
      ])

    dll.add_function('GetIconInfo', 'BOOL',[
      ["DWORD","hIcon","in"],
      ["PBLOB","piconinfo","out"],
      ])

    dll.add_function('GetInputState', 'BOOL',[
      ])

    dll.add_function('GetKBCodePage', 'DWORD',[
      ])

    dll.add_function('GetKeyNameTextA', 'DWORD',[
      ["DWORD","lParam","in"],
      ["PCHAR","lpString","out"],
      ["DWORD","cchSize","in"],
      ])

    dll.add_function('GetKeyNameTextW', 'DWORD',[
      ["DWORD","lParam","in"],
      ["PWCHAR","lpString","out"],
      ["DWORD","cchSize","in"],
      ])

    dll.add_function('GetKeyState', 'WORD',[
      ["DWORD","nVirtKey","in"],
      ])

    dll.add_function('GetKeyboardLayout', 'DWORD',[
      ["DWORD","idThread","in"],
      ])

    dll.add_function('GetKeyboardType', 'DWORD',[
      ["DWORD","nTypeFlag","in"],
      ])

    dll.add_function('GetLastActivePopup', 'DWORD',[
      ["DWORD","hWnd","in"],
      ])

    dll.add_function('GetLastInputInfo', 'BOOL',[
      ["PBLOB","plii","out"],
      ])

    dll.add_function('GetLayeredWindowAttributes', 'BOOL',[
      ["DWORD","hwnd","in"],
      ["PDWORD","pcrKey","out"],
      ["PBLOB","pbAlpha","out"],
      ["PDWORD","pdwFlags","out"],
      ])

    dll.add_function('GetListBoxInfo', 'DWORD',[
      ["DWORD","hwnd","in"],
      ])

    dll.add_function('GetMenu', 'DWORD',[
      ["DWORD","hWnd","in"],
      ])

    dll.add_function('GetMenuBarInfo', 'BOOL',[
      ["DWORD","hwnd","in"],
      ["DWORD","idObject","in"],
      ["DWORD","idItem","in"],
      ["PBLOB","pmbi","inout"],
      ])

    dll.add_function('GetMenuCheckMarkDimensions', 'DWORD',[
      ])

    dll.add_function('GetMenuDefaultItem', 'DWORD',[
      ["DWORD","hMenu","in"],
      ["DWORD","fByPos","in"],
      ["DWORD","gmdiFlags","in"],
      ])

    dll.add_function('GetMenuInfo', 'BOOL',[
      ["DWORD","param0","in"],
      ["PBLOB","param1","inout"],
      ])

    dll.add_function('GetMenuItemCount', 'DWORD',[
      ["DWORD","hMenu","in"],
      ])

    dll.add_function('GetMenuItemID', 'DWORD',[
      ["DWORD","hMenu","in"],
      ["DWORD","nPos","in"],
      ])

    dll.add_function('GetMenuItemInfoA', 'BOOL',[
      ["DWORD","hmenu","in"],
      ["DWORD","item","in"],
      ["BOOL","fByPosition","in"],
      ["PBLOB","lpmii","inout"],
      ])

    dll.add_function('GetMenuItemInfoW', 'BOOL',[
      ["DWORD","hmenu","in"],
      ["DWORD","item","in"],
      ["BOOL","fByPosition","in"],
      ["PBLOB","lpmii","inout"],
      ])

    dll.add_function('GetMenuItemRect', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["DWORD","hMenu","in"],
      ["DWORD","uItem","in"],
      ["PBLOB","lprcItem","out"],
      ])

    dll.add_function('GetMenuState', 'DWORD',[
      ["DWORD","hMenu","in"],
      ["DWORD","uId","in"],
      ["DWORD","uFlags","in"],
      ])

    dll.add_function('GetMenuStringA', 'DWORD',[
      ["DWORD","hMenu","in"],
      ["DWORD","uIDItem","in"],
      ["PCHAR","lpString","out"],
      ["DWORD","cchMax","in"],
      ["DWORD","flags","in"],
      ])

    dll.add_function('GetMenuStringW', 'DWORD',[
      ["DWORD","hMenu","in"],
      ["DWORD","uIDItem","in"],
      ["PWCHAR","lpString","out"],
      ["DWORD","cchMax","in"],
      ["DWORD","flags","in"],
      ])

    dll.add_function('GetMessageA', 'BOOL',[
      ["PBLOB","lpMsg","out"],
      ["DWORD","hWnd","in"],
      ["DWORD","wMsgFilterMin","in"],
      ["DWORD","wMsgFilterMax","in"],
      ])

    dll.add_function('GetMessageExtraInfo', 'DWORD',[
      ])

    dll.add_function('GetMessagePos', 'DWORD',[
      ])

    dll.add_function('GetMessageTime', 'DWORD',[
      ])

    dll.add_function('GetMessageW', 'BOOL',[
      ["PBLOB","lpMsg","out"],
      ["DWORD","hWnd","in"],
      ["DWORD","wMsgFilterMin","in"],
      ["DWORD","wMsgFilterMax","in"],
      ])

    dll.add_function('GetMonitorInfoA', 'BOOL',[
      ["DWORD","hMonitor","in"],
      ["PBLOB","lpmi","inout"],
      ])

    dll.add_function('GetMonitorInfoW', 'BOOL',[
      ["DWORD","hMonitor","in"],
      ["PBLOB","lpmi","inout"],
      ])

    dll.add_function('GetMouseMovePointsEx', 'DWORD',[
      ["DWORD","cbSize","in"],
      ["PBLOB","lppt","in"],
      ["PBLOB","lpptBuf","out"],
      ["DWORD","nBufPoints","in"],
      ["DWORD","resolution","in"],
      ])

    dll.add_function('GetNextDlgGroupItem', 'DWORD',[
      ["DWORD","hDlg","in"],
      ["DWORD","hCtl","in"],
      ["BOOL","bPrevious","in"],
      ])

    dll.add_function('GetNextDlgTabItem', 'DWORD',[
      ["DWORD","hDlg","in"],
      ["DWORD","hCtl","in"],
      ["BOOL","bPrevious","in"],
      ])

    dll.add_function('GetOpenClipboardWindow', 'DWORD',[
      ])

    dll.add_function('GetParent', 'DWORD',[
      ["DWORD","hWnd","in"],
      ])

    dll.add_function('GetPriorityClipboardFormat', 'DWORD',[
      ["PDWORD","paFormatPriorityList","in"],
      ["DWORD","cFormats","in"],
      ])

    dll.add_function('GetProcessDefaultLayout', 'BOOL',[
      ["PDWORD","pdwDefaultLayout","out"],
      ])

    dll.add_function('GetProcessWindowStation', 'DWORD',[
      ])

    dll.add_function('GetPropA', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["PCHAR","lpString","in"],
      ])

    dll.add_function('GetPropW', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["PWCHAR","lpString","in"],
      ])

    dll.add_function('GetQueueStatus', 'DWORD',[
      ["DWORD","flags","in"],
      ])

    dll.add_function('GetRawInputBuffer', 'DWORD',[
      ["PBLOB","pData","out"],
      ["PDWORD","pcbSize","inout"],
      ["DWORD","cbSizeHeader","in"],
      ])

    dll.add_function('GetRawInputData', 'DWORD',[
      ["DWORD","hRawInput","in"],
      ["DWORD","uiCommand","in"],
      ["PBLOB","pData","out"],
      ["PDWORD","pcbSize","inout"],
      ["DWORD","cbSizeHeader","in"],
      ])

    dll.add_function('GetRawInputDeviceInfoA', 'DWORD',[
      ["DWORD","hDevice","in"],
      ["DWORD","uiCommand","in"],
      ["PBLOB","pData","inout"],
      ["PDWORD","pcbSize","inout"],
      ])

    dll.add_function('GetRawInputDeviceInfoW', 'DWORD',[
      ["DWORD","hDevice","in"],
      ["DWORD","uiCommand","in"],
      ["PBLOB","pData","inout"],
      ["PDWORD","pcbSize","inout"],
      ])

    dll.add_function('GetRawInputDeviceList', 'DWORD',[
      ["PBLOB","pRawInputDeviceList","out"],
      ["PDWORD","puiNumDevices","inout"],
      ["DWORD","cbSize","in"],
      ])

    dll.add_function('GetRegisteredRawInputDevices', 'DWORD',[
      ["PBLOB","pRawInputDevices","out"],
      ["PDWORD","puiNumDevices","inout"],
      ["DWORD","cbSize","in"],
      ])

    dll.add_function('GetScrollBarInfo', 'BOOL',[
      ["DWORD","hwnd","in"],
      ["DWORD","idObject","in"],
      ["PBLOB","psbi","inout"],
      ])

    dll.add_function('GetScrollInfo', 'BOOL',[
      ["DWORD","hwnd","in"],
      ["DWORD","nBar","in"],
      ["PBLOB","lpsi","inout"],
      ])

    dll.add_function('GetScrollPos', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","nBar","in"],
      ])

    dll.add_function('GetScrollRange', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["DWORD","nBar","in"],
      ["PDWORD","lpMinPos","out"],
      ["PDWORD","lpMaxPos","out"],
      ])

    dll.add_function('GetShellWindow', 'DWORD',[
      ])

    dll.add_function('GetSubMenu', 'DWORD',[
      ["DWORD","hMenu","in"],
      ["DWORD","nPos","in"],
      ])

    dll.add_function('GetSysColor', 'DWORD',[
      ["DWORD","nIndex","in"],
      ])

    dll.add_function('GetSysColorBrush', 'DWORD',[
      ["DWORD","nIndex","in"],
      ])

    dll.add_function('GetSystemMenu', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["BOOL","bRevert","in"],
      ])

    dll.add_function('GetSystemMetrics', 'DWORD',[
      ["DWORD","nIndex","in"],
      ])

    dll.add_function('GetThreadDesktop', 'DWORD',[
      ["DWORD","dwThreadId","in"],
      ])

    dll.add_function('GetTitleBarInfo', 'BOOL',[
      ["DWORD","hwnd","in"],
      ["PBLOB","pti","inout"],
      ])

    dll.add_function('GetTopWindow', 'DWORD',[
      ["DWORD","hWnd","in"],
      ])

    dll.add_function('GetUpdateRect', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["PBLOB","lpRect","out"],
      ["BOOL","bErase","in"],
      ])

    dll.add_function('GetUpdateRgn', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","hRgn","in"],
      ["BOOL","bErase","in"],
      ])

    dll.add_function('GetUserObjectInformationA', 'BOOL',[
      ["DWORD","hObj","in"],
      ["DWORD","nIndex","in"],
      ["PBLOB","pvInfo","out"],
      ["DWORD","nLength","in"],
      ["PDWORD","lpnLengthNeeded","out"],
      ])

    dll.add_function('GetUserObjectInformationW', 'BOOL',[
      ["DWORD","hObj","in"],
      ["DWORD","nIndex","in"],
      ["PBLOB","pvInfo","out"],
      ["DWORD","nLength","in"],
      ["PDWORD","lpnLengthNeeded","out"],
      ])

    dll.add_function('GetUserObjectSecurity', 'BOOL',[
      ["DWORD","hObj","in"],
      ["PBLOB","pSIRequested","in"],
      ["PBLOB","pSID","out"],
      ["DWORD","nLength","in"],
      ["PDWORD","lpnLengthNeeded","out"],
      ])

    dll.add_function('GetWindow', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","uCmd","in"],
      ])

    dll.add_function('GetWindowContextHelpId', 'DWORD',[
      ["DWORD","param0","in"],
      ])

    dll.add_function('GetWindowDC', 'DWORD',[
      ["DWORD","hWnd","in"],
      ])

    dll.add_function('GetWindowInfo', 'BOOL',[
      ["DWORD","hwnd","in"],
      ["PBLOB","pwi","inout"],
      ])

    dll.add_function('GetWindowLongA', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","nIndex","in"],
      ])

    dll.add_function('GetWindowLongW', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","nIndex","in"],
      ])

    dll.add_function('GetWindowModuleFileNameA', 'DWORD',[
      ["DWORD","hwnd","in"],
      ["PCHAR","pszFileName","out"],
      ["DWORD","cchFileNameMax","in"],
      ])

    dll.add_function('GetWindowModuleFileNameW', 'DWORD',[
      ["DWORD","hwnd","in"],
      ["PWCHAR","pszFileName","out"],
      ["DWORD","cchFileNameMax","in"],
      ])

    dll.add_function('GetWindowPlacement', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["PBLOB","lpwndpl","inout"],
      ])

    dll.add_function('GetWindowRect', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["PBLOB","lpRect","out"],
      ])

    dll.add_function('GetWindowRgn', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","hRgn","in"],
      ])

    dll.add_function('GetWindowRgnBox', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["PBLOB","lprc","out"],
      ])

    dll.add_function('GetWindowTextA', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["PCHAR","lpString","out"],
      ["DWORD","nMaxCount","in"],
      ])

    dll.add_function('GetWindowTextLengthA', 'DWORD',[
      ["DWORD","hWnd","in"],
      ])

    dll.add_function('GetWindowTextLengthW', 'DWORD',[
      ["DWORD","hWnd","in"],
      ])

    dll.add_function('GetWindowTextW', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["PWCHAR","lpString","out"],
      ["DWORD","nMaxCount","in"],
      ])

    dll.add_function('GetWindowThreadProcessId', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["PDWORD","lpdwProcessId","out"],
      ])

    dll.add_function('GetWindowWord', 'WORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","nIndex","in"],
      ])

    dll.add_function('GrayStringA', 'BOOL',[
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

    dll.add_function('GrayStringW', 'BOOL',[
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

    dll.add_function('HideCaret', 'BOOL',[
      ["DWORD","hWnd","in"],
      ])

    dll.add_function('HiliteMenuItem', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["DWORD","hMenu","in"],
      ["DWORD","uIDHiliteItem","in"],
      ["DWORD","uHilite","in"],
      ])

    dll.add_function('InSendMessage', 'BOOL',[
      ])

    dll.add_function('InSendMessageEx', 'DWORD',[
      ["PBLOB","lpReserved","inout"],
      ])

    dll.add_function('InflateRect', 'BOOL',[
      ["PBLOB","lprc","inout"],
      ["DWORD","dx","in"],
      ["DWORD","dy","in"],
      ])

    dll.add_function('InsertMenuA', 'BOOL',[
      ["DWORD","hMenu","in"],
      ["DWORD","uPosition","in"],
      ["DWORD","uFlags","in"],
      ["DWORD","uIDNewItem","in"],
      ["PCHAR","lpNewItem","in"],
      ])

    dll.add_function('InsertMenuItemW', 'BOOL',[
      ["DWORD","hmenu","in"],
      ["DWORD","item","in"],
      ["BOOL","fByPosition","in"],
      ["PBLOB","lpmi","in"],
      ])

    dll.add_function('InsertMenuW', 'BOOL',[
      ["DWORD","hMenu","in"],
      ["DWORD","uPosition","in"],
      ["DWORD","uFlags","in"],
      ["DWORD","uIDNewItem","in"],
      ["PWCHAR","lpNewItem","in"],
      ])

    dll.add_function('InternalGetWindowText', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["PWCHAR","pString","out"],
      ["DWORD","cchMaxCount","in"],
      ])

    dll.add_function('IntersectRect', 'BOOL',[
      ["PBLOB","lprcDst","out"],
      ["PBLOB","lprcSrc1","in"],
      ["PBLOB","lprcSrc2","in"],
      ])

    dll.add_function('InvalidateRect', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["PBLOB","lpRect","in"],
      ["BOOL","bErase","in"],
      ])

    dll.add_function('InvalidateRgn', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["DWORD","hRgn","in"],
      ["BOOL","bErase","in"],
      ])

    dll.add_function('InvertRect', 'BOOL',[
      ["DWORD","hDC","in"],
      ["PBLOB","lprc","in"],
      ])

    dll.add_function('IsCharAlphaA', 'BOOL',[
      ["BYTE","ch","in"],
      ])

    dll.add_function('IsCharAlphaNumericA', 'BOOL',[
      ["BYTE","ch","in"],
      ])

    dll.add_function('IsCharAlphaNumericW', 'BOOL',[
      ["WORD","ch","in"],
      ])

    dll.add_function('IsCharAlphaW', 'BOOL',[
      ["WORD","ch","in"],
      ])

    dll.add_function('IsCharLowerA', 'BOOL',[
      ["BYTE","ch","in"],
      ])

    dll.add_function('IsCharLowerW', 'BOOL',[
      ["WORD","ch","in"],
      ])

    dll.add_function('IsCharUpperA', 'BOOL',[
      ["BYTE","ch","in"],
      ])

    dll.add_function('IsCharUpperW', 'BOOL',[
      ["WORD","ch","in"],
      ])

    dll.add_function('IsChild', 'BOOL',[
      ["DWORD","hWndParent","in"],
      ["DWORD","hWnd","in"],
      ])

    dll.add_function('IsClipboardFormatAvailable', 'BOOL',[
      ["DWORD","format","in"],
      ])

    dll.add_function('IsDialogMessageA', 'BOOL',[
      ["DWORD","hDlg","in"],
      ["PBLOB","lpMsg","in"],
      ])

    dll.add_function('IsDialogMessageW', 'BOOL',[
      ["DWORD","hDlg","in"],
      ["PBLOB","lpMsg","in"],
      ])

    dll.add_function('IsDlgButtonChecked', 'DWORD',[
      ["DWORD","hDlg","in"],
      ["DWORD","nIDButton","in"],
      ])

    dll.add_function('IsGUIThread', 'BOOL',[
      ["BOOL","bConvert","in"],
      ])

    dll.add_function('IsHungAppWindow', 'BOOL',[
      ["DWORD","hwnd","in"],
      ])

    dll.add_function('IsIconic', 'BOOL',[
      ["DWORD","hWnd","in"],
      ])

    dll.add_function('IsMenu', 'BOOL',[
      ["DWORD","hMenu","in"],
      ])

    dll.add_function('IsRectEmpty', 'BOOL',[
      ["PBLOB","lprc","in"],
      ])

    dll.add_function('IsWinEventHookInstalled', 'BOOL',[
      ["DWORD","event","in"],
      ])

    dll.add_function('IsWindow', 'BOOL',[
      ["DWORD","hWnd","in"],
      ])

    dll.add_function('IsWindowEnabled', 'BOOL',[
      ["DWORD","hWnd","in"],
      ])

    dll.add_function('IsWindowUnicode', 'BOOL',[
      ["DWORD","hWnd","in"],
      ])

    dll.add_function('IsWindowVisible', 'BOOL',[
      ["DWORD","hWnd","in"],
      ])

    dll.add_function('IsWow64Message', 'BOOL',[
      ])

    dll.add_function('IsZoomed', 'BOOL',[
      ["DWORD","hWnd","in"],
      ])

    dll.add_function('KillTimer', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["DWORD","uIDEvent","in"],
      ])

    dll.add_function('LoadAcceleratorsA', 'DWORD',[
      ["DWORD","hInstance","in"],
      ["PCHAR","lpTableName","in"],
      ])

    dll.add_function('LoadAcceleratorsW', 'DWORD',[
      ["DWORD","hInstance","in"],
      ["PWCHAR","lpTableName","in"],
      ])

    dll.add_function('LoadBitmapA', 'DWORD',[
      ["DWORD","hInstance","in"],
      ["PCHAR","lpBitmapName","in"],
      ])

    dll.add_function('LoadBitmapW', 'DWORD',[
      ["DWORD","hInstance","in"],
      ["PWCHAR","lpBitmapName","in"],
      ])

    dll.add_function('LoadCursorA', 'DWORD',[
      ["DWORD","hInstance","in"],
      ["PCHAR","lpCursorName","in"],
      ])

    dll.add_function('LoadCursorFromFileA', 'DWORD',[
      ["PCHAR","lpFileName","in"],
      ])

    dll.add_function('LoadCursorFromFileW', 'DWORD',[
      ["PWCHAR","lpFileName","in"],
      ])

    dll.add_function('LoadCursorW', 'DWORD',[
      ["DWORD","hInstance","in"],
      ["PWCHAR","lpCursorName","in"],
      ])

    dll.add_function('LoadIconA', 'DWORD',[
      ["DWORD","hInstance","in"],
      ["PCHAR","lpIconName","in"],
      ])

    dll.add_function('LoadIconW', 'DWORD',[
      ["DWORD","hInstance","in"],
      ["PWCHAR","lpIconName","in"],
      ])

    dll.add_function('LoadImageA', 'DWORD',[
      ["DWORD","hInst","in"],
      ["PCHAR","name","in"],
      ["DWORD","type","in"],
      ["DWORD","cx","in"],
      ["DWORD","cy","in"],
      ["DWORD","fuLoad","in"],
      ])

    dll.add_function('LoadImageW', 'DWORD',[
      ["DWORD","hInst","in"],
      ["PWCHAR","name","in"],
      ["DWORD","type","in"],
      ["DWORD","cx","in"],
      ["DWORD","cy","in"],
      ["DWORD","fuLoad","in"],
      ])

    dll.add_function('LoadKeyboardLayoutA', 'DWORD',[
      ["PCHAR","pwszKLID","in"],
      ["DWORD","Flags","in"],
      ])

    dll.add_function('LoadKeyboardLayoutW', 'DWORD',[
      ["PWCHAR","pwszKLID","in"],
      ["DWORD","Flags","in"],
      ])

    dll.add_function('LoadMenuA', 'DWORD',[
      ["DWORD","hInstance","in"],
      ["PCHAR","lpMenuName","in"],
      ])

    dll.add_function('LoadMenuIndirectA', 'DWORD',[
      ["PBLOB","lpMenuTemplate","in"],
      ])

    dll.add_function('LoadMenuIndirectW', 'DWORD',[
      ["PBLOB","lpMenuTemplate","in"],
      ])

    dll.add_function('LoadMenuW', 'DWORD',[
      ["DWORD","hInstance","in"],
      ["PWCHAR","lpMenuName","in"],
      ])

    dll.add_function('LoadStringA', 'DWORD',[
      ["DWORD","hInstance","in"],
      ["DWORD","uID","in"],
      ["PCHAR","lpBuffer","out"],
      ["DWORD","cchBufferMax","in"],
      ])

    dll.add_function('LoadStringW', 'DWORD',[
      ["DWORD","hInstance","in"],
      ["DWORD","uID","in"],
      ["PWCHAR","lpBuffer","out"],
      ["DWORD","cchBufferMax","in"],
      ])

    dll.add_function('LockSetForegroundWindow', 'BOOL',[
      ["DWORD","uLockCode","in"],
      ])

    dll.add_function('LockWindowUpdate', 'BOOL',[
      ["DWORD","hWndLock","in"],
      ])

    dll.add_function('LockWorkStation', 'BOOL',[
      ])

    dll.add_function('LookupIconIdFromDirectory', 'DWORD',[
      ["PBLOB","presbits","in"],
      ["BOOL","fIcon","in"],
      ])

    dll.add_function('LookupIconIdFromDirectoryEx', 'DWORD',[
      ["PBLOB","presbits","in"],
      ["BOOL","fIcon","in"],
      ["DWORD","cxDesired","in"],
      ["DWORD","cyDesired","in"],
      ["DWORD","Flags","in"],
      ])

    dll.add_function('MapDialogRect', 'BOOL',[
      ["DWORD","hDlg","in"],
      ["PBLOB","lpRect","inout"],
      ])

    dll.add_function('MapVirtualKeyA', 'DWORD',[
      ["DWORD","uCode","in"],
      ["DWORD","uMapType","in"],
      ])

    dll.add_function('MapVirtualKeyExA', 'DWORD',[
      ["DWORD","uCode","in"],
      ["DWORD","uMapType","in"],
      ["DWORD","dwhkl","in"],
      ])

    dll.add_function('MapVirtualKeyExW', 'DWORD',[
      ["DWORD","uCode","in"],
      ["DWORD","uMapType","in"],
      ["DWORD","dwhkl","in"],
      ])

    dll.add_function('MapVirtualKeyW', 'DWORD',[
      ["DWORD","uCode","in"],
      ["DWORD","uMapType","in"],
      ])

    dll.add_function('MapWindowPoints', 'DWORD',[
      ["DWORD","hWndFrom","in"],
      ["DWORD","hWndTo","in"],
      ["PBLOB","lpPoints","in"],
      ["DWORD","cPoints","in"],
      ])

    dll.add_function('MenuItemFromPoint', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","hMenu","in"],
      ["PBLOB","ptScreen","in"],
      ])

    dll.add_function('MessageBeep', 'BOOL',[
      ["DWORD","uType","in"],
      ])

    dll.add_function('MessageBoxA', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["PCHAR","lpText","in"],
      ["PCHAR","lpCaption","in"],
      ["DWORD","uType","in"],
      ])

    dll.add_function('MessageBoxExA', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["PCHAR","lpText","in"],
      ["PCHAR","lpCaption","in"],
      ["DWORD","uType","in"],
      ["WORD","wLanguageId","in"],
      ])

    dll.add_function('MessageBoxExW', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["PWCHAR","lpText","in"],
      ["PWCHAR","lpCaption","in"],
      ["DWORD","uType","in"],
      ["WORD","wLanguageId","in"],
      ])

    dll.add_function('MessageBoxIndirectA', 'DWORD',[
      ["PBLOB","lpmbp","in"],
      ])

    dll.add_function('MessageBoxIndirectW', 'DWORD',[
      ["PBLOB","lpmbp","in"],
      ])

    dll.add_function('MessageBoxW', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["PWCHAR","lpText","in"],
      ["PWCHAR","lpCaption","in"],
      ["DWORD","uType","in"],
      ])

    dll.add_function('ModifyMenuA', 'BOOL',[
      ["DWORD","hMnu","in"],
      ["DWORD","uPosition","in"],
      ["DWORD","uFlags","in"],
      ["DWORD","uIDNewItem","in"],
      ["PCHAR","lpNewItem","in"],
      ])

    dll.add_function('ModifyMenuW', 'BOOL',[
      ["DWORD","hMnu","in"],
      ["DWORD","uPosition","in"],
      ["DWORD","uFlags","in"],
      ["DWORD","uIDNewItem","in"],
      ["PWCHAR","lpNewItem","in"],
      ])

    dll.add_function('MonitorFromPoint', 'DWORD',[
      ["PBLOB","pt","in"],
      ["DWORD","dwFlags","in"],
      ])

    dll.add_function('MonitorFromRect', 'DWORD',[
      ["PBLOB","lprc","in"],
      ["DWORD","dwFlags","in"],
      ])

    dll.add_function('MonitorFromWindow', 'DWORD',[
      ["DWORD","hwnd","in"],
      ["DWORD","dwFlags","in"],
      ])

    dll.add_function('MoveWindow', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["DWORD","X","in"],
      ["DWORD","Y","in"],
      ["DWORD","nWidth","in"],
      ["DWORD","nHeight","in"],
      ["BOOL","bRepaint","in"],
      ])

    dll.add_function('MsgWaitForMultipleObjects', 'DWORD',[
      ["DWORD","nCount","in"],
      ["PDWORD","pHandles","in"],
      ["BOOL","fWaitAll","in"],
      ["DWORD","dwMilliseconds","in"],
      ["DWORD","dwWakeMask","in"],
      ])

    dll.add_function('MsgWaitForMultipleObjectsEx', 'DWORD',[
      ["DWORD","nCount","in"],
      ["PDWORD","pHandles","in"],
      ["DWORD","dwMilliseconds","in"],
      ["DWORD","dwWakeMask","in"],
      ["DWORD","dwFlags","in"],
      ])

    dll.add_function('NotifyWinEvent', 'VOID',[
      ["DWORD","event","in"],
      ["DWORD","hwnd","in"],
      ["DWORD","idObject","in"],
      ["DWORD","idChild","in"],
      ])

    dll.add_function('OemKeyScan', 'DWORD',[
      ["WORD","wOemChar","in"],
      ])

    dll.add_function('OemToCharA', 'BOOL',[
      ["PCHAR","lpszSrc","in"],
      ["PCHAR","lpszDst","out"],
      ])

    dll.add_function('OemToCharBuffA', 'BOOL',[
      ["PCHAR","lpszSrc","in"],
      ["PCHAR","lpszDst","out"],
      ["DWORD","cchDstLength","in"],
      ])

    dll.add_function('OemToCharBuffW', 'BOOL',[
      ["PCHAR","lpszSrc","in"],
      ["PWCHAR","lpszDst","out"],
      ["DWORD","cchDstLength","in"],
      ])

    dll.add_function('OemToCharW', 'BOOL',[
      ["PCHAR","lpszSrc","in"],
      ["PWCHAR","lpszDst","out"],
      ])

    dll.add_function('OffsetRect', 'BOOL',[
      ["PBLOB","lprc","inout"],
      ["DWORD","dx","in"],
      ["DWORD","dy","in"],
      ])

    dll.add_function('OpenClipboard', 'BOOL',[
      ["DWORD","hWndNewOwner","in"],
      ])

    dll.add_function('OpenDesktopA', 'DWORD',[
      ["PCHAR","lpszDesktop","in"],
      ["DWORD","dwFlags","in"],
      ["BOOL","fInherit","in"],
      ["DWORD","dwDesiredAccess","in"],
      ])

    dll.add_function('OpenDesktopW', 'DWORD',[
      ["PWCHAR","lpszDesktop","in"],
      ["DWORD","dwFlags","in"],
      ["BOOL","fInherit","in"],
      ["DWORD","dwDesiredAccess","in"],
      ])

    dll.add_function('OpenIcon', 'BOOL',[
      ["DWORD","hWnd","in"],
      ])

    dll.add_function('OpenInputDesktop', 'DWORD',[
      ["DWORD","dwFlags","in"],
      ["BOOL","fInherit","in"],
      ["DWORD","dwDesiredAccess","in"],
      ])

    dll.add_function('OpenWindowStationA', 'DWORD',[
      ["PCHAR","lpszWinSta","in"],
      ["BOOL","fInherit","in"],
      ["DWORD","dwDesiredAccess","in"],
      ])

    dll.add_function('OpenWindowStationW', 'DWORD',[
      ["PWCHAR","lpszWinSta","in"],
      ["BOOL","fInherit","in"],
      ["DWORD","dwDesiredAccess","in"],
      ])

    dll.add_function('PaintDesktop', 'BOOL',[
      ["DWORD","hdc","in"],
      ])

    dll.add_function('PeekMessageA', 'BOOL',[
      ["PBLOB","lpMsg","out"],
      ["DWORD","hWnd","in"],
      ["DWORD","wMsgFilterMin","in"],
      ["DWORD","wMsgFilterMax","in"],
      ["DWORD","wRemoveMsg","in"],
      ])

    dll.add_function('PeekMessageW', 'BOOL',[
      ["PBLOB","lpMsg","out"],
      ["DWORD","hWnd","in"],
      ["DWORD","wMsgFilterMin","in"],
      ["DWORD","wMsgFilterMax","in"],
      ["DWORD","wRemoveMsg","in"],
      ])

    dll.add_function('PostMessageA', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["DWORD","Msg","in"],
      ["WORD","wParam","in"],
      ["DWORD","lParam","in"],
      ])

    dll.add_function('PostMessageW', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["DWORD","Msg","in"],
      ["WORD","wParam","in"],
      ["DWORD","lParam","in"],
      ])

    dll.add_function('PostQuitMessage', 'VOID',[
      ["DWORD","nExitCode","in"],
      ])

    dll.add_function('PostThreadMessageA', 'BOOL',[
      ["DWORD","idThread","in"],
      ["DWORD","Msg","in"],
      ["WORD","wParam","in"],
      ["DWORD","lParam","in"],
      ])

    dll.add_function('PostThreadMessageW', 'BOOL',[
      ["DWORD","idThread","in"],
      ["DWORD","Msg","in"],
      ["WORD","wParam","in"],
      ["DWORD","lParam","in"],
      ])

    dll.add_function('PrintWindow', 'BOOL',[
      ["DWORD","hwnd","in"],
      ["DWORD","hdcBlt","in"],
      ["DWORD","nFlags","in"],
      ])

    dll.add_function('PrivateExtractIconsA', 'DWORD',[
      ["PCHAR","szFileName","in"],
      ["DWORD","nIconIndex","in"],
      ["DWORD","cxIcon","in"],
      ["DWORD","cyIcon","in"],
      ["PDWORD","phicon","out"],
      ["PDWORD","piconid","out"],
      ["DWORD","nIcons","in"],
      ["DWORD","flags","in"],
      ])

    dll.add_function('PrivateExtractIconsW', 'DWORD',[
      ["PWCHAR","szFileName","in"],
      ["DWORD","nIconIndex","in"],
      ["DWORD","cxIcon","in"],
      ["DWORD","cyIcon","in"],
      ["PDWORD","phicon","out"],
      ["PDWORD","piconid","out"],
      ["DWORD","nIcons","in"],
      ["DWORD","flags","in"],
      ])

    dll.add_function('PtInRect', 'BOOL',[
      ["PBLOB","lprc","in"],
      ["PBLOB","pt","in"],
      ])

    dll.add_function('RealChildWindowFromPoint', 'DWORD',[
      ["DWORD","hwndParent","in"],
      ["PBLOB","ptParentClientCoords","in"],
      ])

    dll.add_function('RealGetWindowClassA', 'DWORD',[
      ["DWORD","hwnd","in"],
      ["PCHAR","ptszClassName","out"],
      ["DWORD","cchClassNameMax","in"],
      ])

    dll.add_function('RealGetWindowClassW', 'DWORD',[
      ["DWORD","hwnd","in"],
      ["PWCHAR","ptszClassName","out"],
      ["DWORD","cchClassNameMax","in"],
      ])

    dll.add_function('RedrawWindow', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["PBLOB","lprcUpdate","in"],
      ["DWORD","hrgnUpdate","in"],
      ["DWORD","flags","in"],
      ])

    dll.add_function('RegisterClassA', 'WORD',[
      ["PBLOB","lpWndClass","in"],
      ])

    dll.add_function('RegisterClassExA', 'WORD',[
      ["PBLOB","param0","in"],
      ])

    dll.add_function('RegisterClassExW', 'WORD',[
      ["PBLOB","param0","in"],
      ])

    dll.add_function('RegisterClassW', 'WORD',[
      ["PBLOB","lpWndClass","in"],
      ])

    dll.add_function('RegisterClipboardFormatA', 'DWORD',[
      ["PCHAR","lpszFormat","in"],
      ])

    dll.add_function('RegisterClipboardFormatW', 'DWORD',[
      ["PWCHAR","lpszFormat","in"],
      ])

    dll.add_function('RegisterDeviceNotificationA', 'DWORD',[
      ["DWORD","hRecipient","in"],
      ["PBLOB","NotificationFilter","in"],
      ["DWORD","Flags","in"],
      ])

    dll.add_function('RegisterDeviceNotificationW', 'DWORD',[
      ["DWORD","hRecipient","in"],
      ["PBLOB","NotificationFilter","in"],
      ["DWORD","Flags","in"],
      ])

    dll.add_function('RegisterHotKey', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["DWORD","id","in"],
      ["DWORD","fsModifiers","in"],
      ["DWORD","vk","in"],
      ])

    dll.add_function('RegisterRawInputDevices', 'BOOL',[
      ["PBLOB","pRawInputDevices","in"],
      ["DWORD","uiNumDevices","in"],
      ["DWORD","cbSize","in"],
      ])

    dll.add_function('RegisterShellHookWindow', 'BOOL',[
      ["DWORD","hwnd","in"],
      ])

    dll.add_function('RegisterWindowMessageA', 'DWORD',[
      ["PCHAR","lpString","in"],
      ])

    dll.add_function('RegisterWindowMessageW', 'DWORD',[
      ["PWCHAR","lpString","in"],
      ])

    dll.add_function('ReleaseCapture', 'BOOL',[
      ])

    dll.add_function('ReleaseDC', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","hDC","in"],
      ])

    dll.add_function('RemoveMenu', 'BOOL',[
      ["DWORD","hMenu","in"],
      ["DWORD","uPosition","in"],
      ["DWORD","uFlags","in"],
      ])

    dll.add_function('RemovePropA', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["PCHAR","lpString","in"],
      ])

    dll.add_function('RemovePropW', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["PWCHAR","lpString","in"],
      ])

    dll.add_function('ReplyMessage', 'BOOL',[
      ["DWORD","lResult","in"],
      ])

    dll.add_function('ScreenToClient', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["PBLOB","lpPoint","inout"],
      ])

    dll.add_function('ScrollDC', 'BOOL',[
      ["DWORD","hDC","in"],
      ["DWORD","dx","in"],
      ["DWORD","dy","in"],
      ["PBLOB","lprcScroll","in"],
      ["PBLOB","lprcClip","in"],
      ["DWORD","hrgnUpdate","in"],
      ["PBLOB","lprcUpdate","out"],
      ])

    dll.add_function('ScrollWindow', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["DWORD","XAmount","in"],
      ["DWORD","YAmount","in"],
      ["PBLOB","lpRect","in"],
      ["PBLOB","lpClipRect","in"],
      ])

    dll.add_function('ScrollWindowEx', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","dx","in"],
      ["DWORD","dy","in"],
      ["PBLOB","prcScroll","in"],
      ["PBLOB","prcClip","in"],
      ["DWORD","hrgnUpdate","in"],
      ["PBLOB","prcUpdate","out"],
      ["DWORD","flags","in"],
      ])

    dll.add_function('SendDlgItemMessageA', 'DWORD',[
      ["DWORD","hDlg","in"],
      ["DWORD","nIDDlgItem","in"],
      ["DWORD","Msg","in"],
      ["WORD","wParam","in"],
      ["DWORD","lParam","in"],
      ])

    dll.add_function('SendDlgItemMessageW', 'DWORD',[
      ["DWORD","hDlg","in"],
      ["DWORD","nIDDlgItem","in"],
      ["DWORD","Msg","in"],
      ["WORD","wParam","in"],
      ["DWORD","lParam","in"],
      ])

    dll.add_function('SendInput', 'DWORD',[
      ["DWORD","cInputs","in"],
      ["PBLOB","pInputs","in"],
      ["DWORD","cbSize","in"],
      ])

    dll.add_function('SendMessageA', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","Msg","in"],
      ["WORD","wParam","in"],
      ["DWORD","lParam","in"],
      ])

    dll.add_function('SendMessageCallbackA', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["DWORD","Msg","in"],
      ["WORD","wParam","in"],
      ["DWORD","lParam","in"],
      ["PBLOB","lpResultCallBack","in"],
      ["PDWORD","dwData","in"],
      ])

    dll.add_function('SendMessageCallbackW', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["DWORD","Msg","in"],
      ["WORD","wParam","in"],
      ["DWORD","lParam","in"],
      ["PBLOB","lpResultCallBack","in"],
      ["PDWORD","dwData","in"],
      ])

    dll.add_function('SendMessageTimeoutA', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","Msg","in"],
      ["WORD","wParam","in"],
      ["DWORD","lParam","in"],
      ["DWORD","fuFlags","in"],
      ["DWORD","uTimeout","in"],
      ["PBLOB","lpdwResult","out"],
      ])

    dll.add_function('SendMessageTimeoutW', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","Msg","in"],
      ["WORD","wParam","in"],
      ["DWORD","lParam","in"],
      ["DWORD","fuFlags","in"],
      ["DWORD","uTimeout","in"],
      ["PBLOB","lpdwResult","out"],
      ])

    dll.add_function('SendMessageW', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","Msg","in"],
      ["WORD","wParam","in"],
      ["DWORD","lParam","in"],
      ])

    dll.add_function('SendNotifyMessageA', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["DWORD","Msg","in"],
      ["WORD","wParam","in"],
      ["DWORD","lParam","in"],
      ])

    dll.add_function('SendNotifyMessageW', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["DWORD","Msg","in"],
      ["WORD","wParam","in"],
      ["DWORD","lParam","in"],
      ])

    dll.add_function('SetActiveWindow', 'DWORD',[
      ["DWORD","hWnd","in"],
      ])

    dll.add_function('SetCapture', 'DWORD',[
      ["DWORD","hWnd","in"],
      ])

    dll.add_function('SetCaretBlinkTime', 'BOOL',[
      ["DWORD","uMSeconds","in"],
      ])

    dll.add_function('SetCaretPos', 'BOOL',[
      ["DWORD","X","in"],
      ["DWORD","Y","in"],
      ])

    dll.add_function('SetClassLongA', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","nIndex","in"],
      ["DWORD","dwNewLong","in"],
      ])

    dll.add_function('SetClassLongW', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","nIndex","in"],
      ["DWORD","dwNewLong","in"],
      ])

    dll.add_function('SetClassWord', 'WORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","nIndex","in"],
      ["WORD","wNewWord","in"],
      ])

    dll.add_function('SetClipboardData', 'DWORD',[
      ["DWORD","uFormat","in"],
      ["DWORD","hMem","in"],
      ])

    dll.add_function('SetClipboardViewer', 'DWORD',[
      ["DWORD","hWndNewViewer","in"],
      ])

    dll.add_function('SetCursor', 'DWORD',[
      ["DWORD","hCursor","in"],
      ])

    dll.add_function('SetCursorPos', 'BOOL',[
      ["DWORD","X","in"],
      ["DWORD","Y","in"],
      ])

    dll.add_function('SetDebugErrorLevel', 'VOID',[
      ["DWORD","dwLevel","in"],
      ])

    dll.add_function('SetDlgItemInt', 'BOOL',[
      ["DWORD","hDlg","in"],
      ["DWORD","nIDDlgItem","in"],
      ["DWORD","uValue","in"],
      ["BOOL","bSigned","in"],
      ])

    dll.add_function('SetDlgItemTextA', 'BOOL',[
      ["DWORD","hDlg","in"],
      ["DWORD","nIDDlgItem","in"],
      ["PCHAR","lpString","in"],
      ])

    dll.add_function('SetDlgItemTextW', 'BOOL',[
      ["DWORD","hDlg","in"],
      ["DWORD","nIDDlgItem","in"],
      ["PWCHAR","lpString","in"],
      ])

    dll.add_function('SetDoubleClickTime', 'BOOL',[
      ["DWORD","param0","in"],
      ])

    dll.add_function('SetFocus', 'DWORD',[
      ["DWORD","hWnd","in"],
      ])

    dll.add_function('SetForegroundWindow', 'BOOL',[
      ["DWORD","hWnd","in"],
      ])

    dll.add_function('SetLastErrorEx', 'VOID',[
      ["DWORD","dwErrCode","in"],
      ["DWORD","dwType","in"],
      ])

    dll.add_function('SetLayeredWindowAttributes', 'BOOL',[
      ["DWORD","hwnd","in"],
      ["DWORD","crKey","in"],
      ["BYTE","bAlpha","in"],
      ["DWORD","dwFlags","in"],
      ])

    dll.add_function('SetMenu', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["DWORD","hMenu","in"],
      ])

    dll.add_function('SetMenuContextHelpId', 'BOOL',[
      ["DWORD","param0","in"],
      ["DWORD","param1","in"],
      ])

    dll.add_function('SetMenuDefaultItem', 'BOOL',[
      ["DWORD","hMenu","in"],
      ["DWORD","uItem","in"],
      ["DWORD","fByPos","in"],
      ])

    dll.add_function('SetMenuInfo', 'BOOL',[
      ["DWORD","param0","in"],
      ["PBLOB","param1","in"],
      ])

    dll.add_function('SetMenuItemBitmaps', 'BOOL',[
      ["DWORD","hMenu","in"],
      ["DWORD","uPosition","in"],
      ["DWORD","uFlags","in"],
      ["DWORD","hBitmapUnchecked","in"],
      ["DWORD","hBitmapChecked","in"],
      ])

    dll.add_function('SetMenuItemInfoW', 'BOOL',[
      ["DWORD","hmenu","in"],
      ["DWORD","item","in"],
      ["BOOL","fByPositon","in"],
      ["PBLOB","lpmii","in"],
      ])

    dll.add_function('SetMessageExtraInfo', 'DWORD',[
      ["DWORD","lParam","in"],
      ])

    dll.add_function('SetMessageQueue', 'BOOL',[
      ["DWORD","cMessagesMax","in"],
      ])

    dll.add_function('SetParent', 'DWORD',[
      ["DWORD","hWndChild","in"],
      ["DWORD","hWndNewParent","in"],
      ])

    dll.add_function('SetProcessDefaultLayout', 'BOOL',[
      ["DWORD","dwDefaultLayout","in"],
      ])

    dll.add_function('SetProcessWindowStation', 'BOOL',[
      ["DWORD","hWinSta","in"],
      ])

    dll.add_function('SetPropA', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["PCHAR","lpString","in"],
      ["DWORD","hData","in"],
      ])

    dll.add_function('SetPropW', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["PWCHAR","lpString","in"],
      ["DWORD","hData","in"],
      ])

    dll.add_function('SetRect', 'BOOL',[
      ["PBLOB","lprc","out"],
      ["DWORD","xLeft","in"],
      ["DWORD","yTop","in"],
      ["DWORD","xRight","in"],
      ["DWORD","yBottom","in"],
      ])

    dll.add_function('SetRectEmpty', 'BOOL',[
      ["PBLOB","lprc","out"],
      ])

    dll.add_function('SetScrollInfo', 'DWORD',[
      ["DWORD","hwnd","in"],
      ["DWORD","nBar","in"],
      ["PBLOB","lpsi","in"],
      ["BOOL","redraw","in"],
      ])

    dll.add_function('SetScrollPos', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","nBar","in"],
      ["DWORD","nPos","in"],
      ["BOOL","bRedraw","in"],
      ])

    dll.add_function('SetScrollRange', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["DWORD","nBar","in"],
      ["DWORD","nMinPos","in"],
      ["DWORD","nMaxPos","in"],
      ["BOOL","bRedraw","in"],
      ])

    dll.add_function('SetSystemCursor', 'BOOL',[
      ["DWORD","hcur","in"],
      ["DWORD","id","in"],
      ])

    dll.add_function('SetThreadDesktop', 'BOOL',[
      ["DWORD","hDesktop","in"],
      ])

    dll.add_function('SetTimer', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","nIDEvent","in"],
      ["DWORD","uElapse","in"],
      ["PBLOB","lpTimerFunc","in"],
      ])

    dll.add_function('SetUserObjectInformationA', 'BOOL',[
      ["DWORD","hObj","in"],
      ["DWORD","nIndex","in"],
      ["PBLOB","pvInfo","in"],
      ["DWORD","nLength","in"],
      ])

    dll.add_function('SetUserObjectInformationW', 'BOOL',[
      ["DWORD","hObj","in"],
      ["DWORD","nIndex","in"],
      ["PBLOB","pvInfo","in"],
      ["DWORD","nLength","in"],
      ])

    dll.add_function('SetUserObjectSecurity', 'BOOL',[
      ["DWORD","hObj","in"],
      ["PBLOB","pSIRequested","in"],
      ["PBLOB","pSID","in"],
      ])

    dll.add_function('SetWindowContextHelpId', 'BOOL',[
      ["DWORD","param0","in"],
      ["DWORD","param1","in"],
      ])

    dll.add_function('SetWindowLongA', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","nIndex","in"],
      ["DWORD","dwNewLong","in"],
      ])

    dll.add_function('SetWindowLongW', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","nIndex","in"],
      ["DWORD","dwNewLong","in"],
      ])

    dll.add_function('SetWindowPlacement', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["PBLOB","lpwndpl","in"],
      ])

    dll.add_function('SetWindowPos', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["DWORD","hWndInsertAfter","in"],
      ["DWORD","X","in"],
      ["DWORD","Y","in"],
      ["DWORD","cx","in"],
      ["DWORD","cy","in"],
      ["DWORD","uFlags","in"],
      ])

    dll.add_function('SetWindowRgn', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","hRgn","in"],
      ["BOOL","bRedraw","in"],
      ])

    dll.add_function('SetWindowTextA', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["PCHAR","lpString","in"],
      ])

    dll.add_function('SetWindowTextW', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["PWCHAR","lpString","in"],
      ])

    dll.add_function('SetWindowWord', 'WORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","nIndex","in"],
      ["WORD","wNewWord","in"],
      ])

    dll.add_function('SetWindowsHookA', 'DWORD',[
      ["DWORD","nFilterType","in"],
      ["DWORD","pfnFilterProc","in"],
      ])

    dll.add_function('SetWindowsHookExA', 'DWORD',[
      ["DWORD","idHook","in"],
      ["DWORD","lpfn","in"],
      ["DWORD","hmod","in"],
      ["DWORD","dwThreadId","in"],
      ])

    dll.add_function('SetWindowsHookExW', 'DWORD',[
      ["DWORD","idHook","in"],
      ["DWORD","lpfn","in"],
      ["DWORD","hmod","in"],
      ["DWORD","dwThreadId","in"],
      ])

    dll.add_function('SetWindowsHookW', 'DWORD',[
      ["DWORD","nFilterType","in"],
      ["DWORD","pfnFilterProc","in"],
      ])

    dll.add_function('ShowCaret', 'BOOL',[
      ["DWORD","hWnd","in"],
      ])

    dll.add_function('ShowCursor', 'DWORD',[
      ["BOOL","bShow","in"],
      ])

    dll.add_function('ShowOwnedPopups', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["BOOL","fShow","in"],
      ])

    dll.add_function('ShowScrollBar', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["DWORD","wBar","in"],
      ["BOOL","bShow","in"],
      ])

    dll.add_function('ShowWindow', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["DWORD","nCmdShow","in"],
      ])

    dll.add_function('ShowWindowAsync', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["DWORD","nCmdShow","in"],
      ])

    dll.add_function('SubtractRect', 'BOOL',[
      ["PBLOB","lprcDst","out"],
      ["PBLOB","lprcSrc1","in"],
      ["PBLOB","lprcSrc2","in"],
      ])

    dll.add_function('SwapMouseButton', 'BOOL',[
      ["BOOL","fSwap","in"],
      ])

    dll.add_function('SwitchDesktop', 'BOOL',[
      ["DWORD","hDesktop","in"],
      ])

    dll.add_function('SwitchToThisWindow', 'VOID',[
      ["DWORD","hwnd","in"],
      ["BOOL","fUnknown","in"],
      ])

    dll.add_function('SystemParametersInfoA', 'BOOL',[
      ["DWORD","uiAction","in"],
      ["DWORD","uiParam","in"],
      ["PBLOB","pvParam","inout"],
      ["DWORD","fWinIni","in"],
      ])

    dll.add_function('SystemParametersInfoW', 'BOOL',[
      ["DWORD","uiAction","in"],
      ["DWORD","uiParam","in"],
      ["PBLOB","pvParam","inout"],
      ["DWORD","fWinIni","in"],
      ])

    dll.add_function('TabbedTextOutA', 'DWORD',[
      ["DWORD","hdc","in"],
      ["DWORD","x","in"],
      ["DWORD","y","in"],
      ["PCHAR","lpString","in"],
      ["DWORD","chCount","in"],
      ["DWORD","nTabPositions","in"],
      ["PDWORD","lpnTabStopPositions","in"],
      ["DWORD","nTabOrigin","in"],
      ])

    dll.add_function('TabbedTextOutW', 'DWORD',[
      ["DWORD","hdc","in"],
      ["DWORD","x","in"],
      ["DWORD","y","in"],
      ["PWCHAR","lpString","in"],
      ["DWORD","chCount","in"],
      ["DWORD","nTabPositions","in"],
      ["PDWORD","lpnTabStopPositions","in"],
      ["DWORD","nTabOrigin","in"],
      ])

    dll.add_function('TileWindows', 'WORD',[
      ["DWORD","hwndParent","in"],
      ["DWORD","wHow","in"],
      ["PBLOB","lpRect","in"],
      ["DWORD","cKids","in"],
      ["PDWORD","lpKids","in"],
      ])

    dll.add_function('ToAscii', 'DWORD',[
      ["DWORD","uVirtKey","in"],
      ["DWORD","uScanCode","in"],
      ["PBLOB","lpKeyState","in"],
      ["PBLOB","lpChar","out"],
      ["DWORD","uFlags","in"],
      ])

    dll.add_function('ToAsciiEx', 'DWORD',[
      ["DWORD","uVirtKey","in"],
      ["DWORD","uScanCode","in"],
      ["PBLOB","lpKeyState","in"],
      ["PBLOB","lpChar","out"],
      ["DWORD","uFlags","in"],
      ["DWORD","dwhkl","in"],
      ])

    dll.add_function('TrackMouseEvent', 'BOOL',[
      ["PBLOB","lpEventTrack","inout"],
      ])

    dll.add_function('TrackPopupMenu', 'BOOL',[
      ["DWORD","hMenu","in"],
      ["DWORD","uFlags","in"],
      ["DWORD","x","in"],
      ["DWORD","y","in"],
      ["DWORD","nReserved","in"],
      ["DWORD","hWnd","in"],
      ["PBLOB","prcRect","in"],
      ])

    dll.add_function('TranslateAcceleratorA', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","hAccTable","in"],
      ["PBLOB","lpMsg","in"],
      ])

    dll.add_function('TranslateAcceleratorW', 'DWORD',[
      ["DWORD","hWnd","in"],
      ["DWORD","hAccTable","in"],
      ["PBLOB","lpMsg","in"],
      ])

    dll.add_function('TranslateMDISysAccel', 'BOOL',[
      ["DWORD","hWndClient","in"],
      ["PBLOB","lpMsg","in"],
      ])

    dll.add_function('TranslateMessage', 'BOOL',[
      ["PBLOB","lpMsg","in"],
      ])

    dll.add_function('UnhookWinEvent', 'BOOL',[
      ["DWORD","hWinEventHook","in"],
      ])

    dll.add_function('UnhookWindowsHook', 'BOOL',[
      ["DWORD","nCode","in"],
      ["DWORD","pfnFilterProc","in"],
      ])

    dll.add_function('UnhookWindowsHookEx', 'BOOL',[
      ["DWORD","hhk","in"],
      ])

    dll.add_function('UnionRect', 'BOOL',[
      ["PBLOB","lprcDst","out"],
      ["PBLOB","lprcSrc1","in"],
      ["PBLOB","lprcSrc2","in"],
      ])

    dll.add_function('UnloadKeyboardLayout', 'BOOL',[
      ["DWORD","hkl","in"],
      ])

    dll.add_function('UnregisterClassA', 'BOOL',[
      ["PCHAR","lpClassName","in"],
      ["DWORD","hInstance","in"],
      ])

    dll.add_function('UnregisterClassW', 'BOOL',[
      ["PWCHAR","lpClassName","in"],
      ["DWORD","hInstance","in"],
      ])

    dll.add_function('UnregisterDeviceNotification', 'BOOL',[
      ["DWORD","Handle","in"],
      ])

    dll.add_function('UnregisterHotKey', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["DWORD","id","in"],
      ])

    dll.add_function('UpdateWindow', 'BOOL',[
      ["DWORD","hWnd","in"],
      ])

    dll.add_function('UserHandleGrantAccess', 'BOOL',[
      ["DWORD","hUserHandle","in"],
      ["DWORD","hJob","in"],
      ["BOOL","bGrant","in"],
      ])

    dll.add_function('ValidateRect', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["PBLOB","lpRect","in"],
      ])

    dll.add_function('ValidateRgn', 'BOOL',[
      ["DWORD","hWnd","in"],
      ["DWORD","hRgn","in"],
      ])

    dll.add_function('VkKeyScanA', 'WORD',[
      ["BYTE","ch","in"],
      ])

    dll.add_function('VkKeyScanExA', 'WORD',[
      ["BYTE","ch","in"],
      ["DWORD","dwhkl","in"],
      ])

    dll.add_function('VkKeyScanExW', 'WORD',[
      ["WORD","ch","in"],
      ["DWORD","dwhkl","in"],
      ])

    dll.add_function('VkKeyScanW', 'WORD',[
      ["WORD","ch","in"],
      ])

    dll.add_function('WaitForInputIdle', 'DWORD',[
      ["DWORD","hProcess","in"],
      ["DWORD","dwMilliseconds","in"],
      ])

    dll.add_function('WaitMessage', 'BOOL',[
      ])

    dll.add_function('WinHelpA', 'BOOL',[
      ["DWORD","hWndMain","in"],
      ["PCHAR","lpszHelp","in"],
      ["DWORD","uCommand","in"],
      ["PDWORD","dwData","in"],
      ])

    dll.add_function('WinHelpW', 'BOOL',[
      ["DWORD","hWndMain","in"],
      ["PWCHAR","lpszHelp","in"],
      ["DWORD","uCommand","in"],
      ["PDWORD","dwData","in"],
      ])

    dll.add_function('WindowFromDC', 'DWORD',[
      ["DWORD","hDC","in"],
      ])

    dll.add_function('WindowFromPoint', 'DWORD',[
      ["PBLOB","Point","in"],
      ])

    dll.add_function('keybd_event', 'VOID',[
      ["BYTE","bVk","in"],
      ["BYTE","bScan","in"],
      ["DWORD","dwFlags","in"],
      ["PDWORD","dwExtraInfo","in"],
      ])

    dll.add_function('mouse_event', 'VOID',[
      ["DWORD","dwFlags","in"],
      ["DWORD","dx","in"],
      ["DWORD","dy","in"],
      ["DWORD","dwData","in"],
      ["PDWORD","dwExtraInfo","in"],
      ])

    return dll
  end

end

end; end; end; end; end; end; end
