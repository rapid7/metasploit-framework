#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/dynldr'

module Metasm
module Gui
class Win32Gui < DynLdr
  new_api_c <<EOS
#line #{__LINE__}
typedef char CHAR;
typedef unsigned char BYTE;
typedef unsigned short WORD;
typedef unsigned int UINT;
typedef long LONG;
typedef unsigned long ULONG, DWORD;
typedef int BOOL;

typedef intptr_t INT_PTR, LONG_PTR;
typedef uintptr_t UINT_PTR, ULONG_PTR, DWORD_PTR;
typedef LONG_PTR LPARAM;
typedef UINT_PTR WPARAM;
typedef LONG_PTR LRESULT;
typedef const CHAR *LPSTR, *LPCSTR;
typedef void VOID, *PVOID, *LPVOID;

typedef WORD ATOM;
typedef void *HANDLE;
typedef void *HBITMAP;
typedef void *HBRUSH;
typedef void *HCURSOR;
typedef void *HDC;
typedef void *HICON;
typedef void *HINSTANCE;
typedef void *HMENU;
typedef void *HMODULE;
typedef void *HPEN;
typedef void *HWND;

#define DECLSPEC_IMPORT __declspec(dllimport)
#define WINUSERAPI DECLSPEC_IMPORT
#define WINAPI __stdcall
#define CALLBACK __stdcall
#define CONST const
#define __in __attribute__((in))
#define __out __attribute__((out))
#define __opt __attribute__((opt))
#define __inout __in __out
#define __in_opt __in __opt
#define __out_opt __out __opt
#define __in_ecount(c) __in
#define __out_ecount(c) __out
#define __inout_ecount(c) __inout

#define CW_USEDEFAULT       ((int)0x80000000)

#define WS_OVERLAPPED       0x00000000L
#define WS_POPUP            0x80000000L
#define WS_CHILD            0x40000000L
#define WS_MINIMIZE         0x20000000L
#define WS_VISIBLE          0x10000000L
#define WS_DISABLED         0x08000000L
#define WS_CLIPSIBLINGS     0x04000000L
#define WS_CLIPCHILDREN     0x02000000L
#define WS_MAXIMIZE         0x01000000L
#define WS_CAPTION          0x00C00000L     /* WS_BORDER | WS_DLGFRAME  */
#define WS_BORDER           0x00800000L
#define WS_DLGFRAME         0x00400000L
#define WS_VSCROLL          0x00200000L
#define WS_HSCROLL          0x00100000L
#define WS_SYSMENU          0x00080000L
#define WS_THICKFRAME       0x00040000L
#define WS_GROUP            0x00020000L
#define WS_TABSTOP          0x00010000L
#define WS_MINIMIZEBOX      0x00020000L
#define WS_MAXIMIZEBOX      0x00010000L
#define WS_TILED            WS_OVERLAPPED
#define WS_ICONIC           WS_MINIMIZE
#define WS_SIZEBOX          WS_THICKFRAME
#define WS_TILEDWINDOW      WS_OVERLAPPEDWINDOW
#define WS_OVERLAPPEDWINDOW (WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX)
#define WS_POPUPWINDOW      (WS_POPUP |  WS_BORDER | WS_SYSMENU)
#define WS_CHILDWINDOW      (WS_CHILD)

#define WS_EX_DLGMODALFRAME     0x00000001L
#define WS_EX_NOPARENTNOTIFY    0x00000004L
#define WS_EX_TOPMOST           0x00000008L
#define WS_EX_ACCEPTFILES       0x00000010L
#define WS_EX_TRANSPARENT       0x00000020L
#define WS_EX_MDICHILD          0x00000040L
#define WS_EX_TOOLWINDOW        0x00000080L
#define WS_EX_WINDOWEDGE        0x00000100L
#define WS_EX_CLIENTEDGE        0x00000200L
#define WS_EX_CONTEXTHELP       0x00000400L
#define WS_EX_RIGHT             0x00001000L
#define WS_EX_LEFT              0x00000000L
#define WS_EX_RTLREADING        0x00002000L
#define WS_EX_LTRREADING        0x00000000L
#define WS_EX_LEFTSCROLLBAR     0x00004000L
#define WS_EX_RIGHTSCROLLBAR    0x00000000L
#define WS_EX_CONTROLPARENT     0x00010000L
#define WS_EX_STATICEDGE        0x00020000L
#define WS_EX_APPWINDOW         0x00040000L
#define WS_EX_OVERLAPPEDWINDOW  (WS_EX_WINDOWEDGE | WS_EX_CLIENTEDGE)
#define WS_EX_PALETTEWINDOW     (WS_EX_WINDOWEDGE | WS_EX_TOOLWINDOW | WS_EX_TOPMOST)
#define WS_EX_LAYERED           0x00080000L
#define WS_EX_NOINHERITEDLAYOUT 0x00100000L
#define WS_EX_LAYOUTRTL         0x00400000L
#define WS_EX_COMPOSITED        0x02000000L
#define WS_EX_NOACTIVATE        0x08000000L

#define WM_NULL                         0x0000
#define WM_CREATE                       0x0001
#define WM_DESTROY                      0x0002
#define WM_MOVE                         0x0003
#define WM_SIZE                         0x0005

#define WM_ACTIVATE                     0x0006
#define     WA_INACTIVE     0
#define     WA_ACTIVE       1
#define     WA_CLICKACTIVE  2

#define WM_SETFOCUS                     0x0007
#define WM_KILLFOCUS                    0x0008
#define WM_ENABLE                       0x000A
#define WM_SETREDRAW                    0x000B
#define WM_SETTEXT                      0x000C
#define WM_GETTEXT                      0x000D
#define WM_GETTEXTLENGTH                0x000E
#define WM_PAINT                        0x000F
#define WM_CLOSE                        0x0010
#define WM_QUERYENDSESSION              0x0011
#define WM_QUERYOPEN                    0x0013
#define WM_ENDSESSION                   0x0016
#define WM_QUIT                         0x0012
#define WM_ERASEBKGND                   0x0014
#define WM_SYSCOLORCHANGE               0x0015
#define WM_SHOWWINDOW                   0x0018
#define WM_WININICHANGE                 0x001A
#define WM_SETTINGCHANGE                WM_WININICHANGE
#define WM_DEVMODECHANGE                0x001B
#define WM_ACTIVATEAPP                  0x001C
#define WM_FONTCHANGE                   0x001D
#define WM_TIMECHANGE                   0x001E
#define WM_CANCELMODE                   0x001F
#define WM_SETCURSOR                    0x0020
#define WM_MOUSEACTIVATE                0x0021
#define WM_CHILDACTIVATE                0x0022
#define WM_QUEUESYNC                    0x0023
#define WM_GETMINMAXINFO                0x0024
typedef struct tagPOINT {
    LONG  x;
    LONG  y;
} POINT, *PPOINT, *LPPOINT;

#define WM_PAINTICON                    0x0026
#define WM_ICONERASEBKGND               0x0027
#define WM_NEXTDLGCTL                   0x0028
#define WM_SPOOLERSTATUS                0x002A
#define WM_DRAWITEM                     0x002B
#define WM_MEASUREITEM                  0x002C
#define WM_DELETEITEM                   0x002D
#define WM_VKEYTOITEM                   0x002E
#define WM_CHARTOITEM                   0x002F
#define WM_SETFONT                      0x0030
#define WM_GETFONT                      0x0031
#define WM_SETHOTKEY                    0x0032
#define WM_GETHOTKEY                    0x0033
#define WM_QUERYDRAGICON                0x0037
#define WM_COMPAREITEM                  0x0039
#define WM_GETOBJECT                    0x003D
#define WM_COMPACTING                   0x0041
#define WM_COMMNOTIFY                   0x0044
#define WM_WINDOWPOSCHANGING            0x0046
#define WM_WINDOWPOSCHANGED             0x0047
#define WM_POWER                        0x0048
#define PWR_OK              1
#define PWR_FAIL            (-1)
#define PWR_SUSPENDREQUEST  1
#define PWR_SUSPENDRESUME   2
#define PWR_CRITICALRESUME  3
#define WM_COPYDATA                     0x004A
#define WM_CANCELJOURNAL                0x004B
#define WM_NOTIFY                       0x004E
#define WM_INPUTLANGCHANGEREQUEST       0x0050
#define WM_INPUTLANGCHANGE              0x0051
#define WM_TCARD                        0x0052
#define WM_HELP                         0x0053
#define WM_USERCHANGED                  0x0054
#define WM_NOTIFYFORMAT                 0x0055
#define NFR_ANSI                             1
#define NFR_UNICODE                          2
#define NF_QUERY                             3
#define NF_REQUERY                           4
#define WM_CONTEXTMENU                  0x007B
#define WM_STYLECHANGING                0x007C
#define WM_STYLECHANGED                 0x007D
#define WM_DISPLAYCHANGE                0x007E
#define WM_GETICON                      0x007F
#define WM_SETICON                      0x0080
#define WM_NCCREATE                     0x0081
#define WM_NCDESTROY                    0x0082
#define WM_NCCALCSIZE                   0x0083
#define WM_NCHITTEST                    0x0084
#define WM_NCPAINT                      0x0085
#define WM_NCACTIVATE                   0x0086
#define WM_GETDLGCODE                   0x0087
#define WM_SYNCPAINT                    0x0088
#define WM_NCMOUSEMOVE                  0x00A0
#define WM_NCLBUTTONDOWN                0x00A1
#define WM_NCLBUTTONUP                  0x00A2
#define WM_NCLBUTTONDBLCLK              0x00A3
#define WM_NCRBUTTONDOWN                0x00A4
#define WM_NCRBUTTONUP                  0x00A5
#define WM_NCRBUTTONDBLCLK              0x00A6
#define WM_NCMBUTTONDOWN                0x00A7
#define WM_NCMBUTTONUP                  0x00A8
#define WM_NCMBUTTONDBLCLK              0x00A9
#define WM_NCXBUTTONDOWN                0x00AB
#define WM_NCXBUTTONUP                  0x00AC
#define WM_NCXBUTTONDBLCLK              0x00AD
#define WM_INPUT                        0x00FF
#define WM_KEYFIRST                     0x0100
#define WM_KEYDOWN                      0x0100
#define WM_KEYUP                        0x0101
#define WM_CHAR                         0x0102
#define WM_DEADCHAR                     0x0103
#define WM_SYSKEYDOWN                   0x0104
#define WM_SYSKEYUP                     0x0105
#define WM_SYSCHAR                      0x0106
#define WM_SYSDEADCHAR                  0x0107
#define WM_UNICHAR                      0x0109
#define WM_KEYLAST                      0x0109
#define UNICODE_NOCHAR                  0xFFFF
#define WM_IME_STARTCOMPOSITION         0x010D
#define WM_IME_ENDCOMPOSITION           0x010E
#define WM_IME_COMPOSITION              0x010F
#define WM_IME_KEYLAST                  0x010F

#define WM_INITDIALOG                   0x0110
#define WM_COMMAND                      0x0111
#define WM_SYSCOMMAND                   0x0112
#define WM_TIMER                        0x0113
#define WM_HSCROLL                      0x0114
#define WM_VSCROLL                      0x0115
#define WM_INITMENU                     0x0116
#define WM_INITMENUPOPUP                0x0117
#define WM_MENUSELECT                   0x011F
#define WM_MENUCHAR                     0x0120
#define WM_ENTERIDLE                    0x0121
#define WM_MENURBUTTONUP                0x0122
#define WM_MENUDRAG                     0x0123
#define WM_MENUGETOBJECT                0x0124
#define WM_UNINITMENUPOPUP              0x0125
#define WM_MENUCOMMAND                  0x0126
#define WM_CHANGEUISTATE                0x0127
#define WM_UPDATEUISTATE                0x0128
#define WM_QUERYUISTATE                 0x0129
#define UIS_SET                         1
#define UIS_CLEAR                       2
#define UIS_INITIALIZE                  3
#define UISF_HIDEFOCUS                  0x1
#define UISF_HIDEACCEL                  0x2
#define WM_CTLCOLORMSGBOX               0x0132
#define WM_CTLCOLOREDIT                 0x0133
#define WM_CTLCOLORLISTBOX              0x0134
#define WM_CTLCOLORBTN                  0x0135
#define WM_CTLCOLORDLG                  0x0136
#define WM_CTLCOLORSCROLLBAR            0x0137
#define WM_CTLCOLORSTATIC               0x0138
#define MN_GETHMENU                     0x01E1
#define WM_MOUSEFIRST                   0x0200
#define WM_MOUSEMOVE                    0x0200
#define WM_LBUTTONDOWN                  0x0201
#define WM_LBUTTONUP                    0x0202
#define WM_LBUTTONDBLCLK                0x0203
#define WM_RBUTTONDOWN                  0x0204
#define WM_RBUTTONUP                    0x0205
#define WM_RBUTTONDBLCLK                0x0206
#define WM_MBUTTONDOWN                  0x0207
#define WM_MBUTTONUP                    0x0208
#define WM_MBUTTONDBLCLK                0x0209
#define WM_MOUSEWHEEL                   0x020A
#define WM_XBUTTONDOWN                  0x020B
#define WM_XBUTTONUP                    0x020C
#define WM_XBUTTONDBLCLK                0x020D
#define WHEEL_DELTA                     120

#define WHEEL_PAGESCROLL                (UINT_MAX)
#define GET_WHEEL_DELTA_WPARAM(wParam)  ((short)HIWORD(wParam))
#define GET_KEYSTATE_WPARAM(wParam)     (LOWORD(wParam))
#define GET_NCHITTEST_WPARAM(wParam)    ((short)LOWORD(wParam))
#define GET_XBUTTON_WPARAM(wParam)      (HIWORD(wParam))

#define XBUTTON1      0x0001
#define XBUTTON2      0x0002

#define WM_PARENTNOTIFY                 0x0210
#define WM_ENTERMENULOOP                0x0211
#define WM_EXITMENULOOP                 0x0212
#define WM_NEXTMENU                     0x0213
#define WM_SIZING                       0x0214
#define WM_CAPTURECHANGED               0x0215
#define WM_MOVING                       0x0216
#define WM_DEVICECHANGE                 0x0219
#define WM_MDICREATE                    0x0220
#define WM_MDIDESTROY                   0x0221
#define WM_MDIACTIVATE                  0x0222
#define WM_MDIRESTORE                   0x0223
#define WM_MDINEXT                      0x0224
#define WM_MDIMAXIMIZE                  0x0225
#define WM_MDITILE                      0x0226
#define WM_MDICASCADE                   0x0227
#define WM_MDIICONARRANGE               0x0228
#define WM_MDIGETACTIVE                 0x0229
#define WM_MDISETMENU                   0x0230
#define WM_ENTERSIZEMOVE                0x0231
#define WM_EXITSIZEMOVE                 0x0232
#define WM_DROPFILES                    0x0233
#define WM_MDIREFRESHMENU               0x0234
#define WM_IME_SETCONTEXT               0x0281
#define WM_IME_NOTIFY                   0x0282
#define WM_IME_CONTROL                  0x0283
#define WM_IME_COMPOSITIONFULL          0x0284
#define WM_IME_SELECT                   0x0285
#define WM_IME_CHAR                     0x0286
#define WM_IME_REQUEST                  0x0288
#define WM_IME_KEYDOWN                  0x0290
#define WM_IME_KEYUP                    0x0291
#define WM_NCMOUSEHOVER                 0x02A0
#define WM_MOUSEHOVER                   0x02A1
#define WM_NCMOUSELEAVE                 0x02A2
#define WM_MOUSELEAVE                   0x02A3
#define WM_WTSSESSION_CHANGE            0x02B1
#define WM_TABLET_FIRST                 0x02c0
#define WM_TABLET_LAST                  0x02df
#define WM_CUT                          0x0300
#define WM_COPY                         0x0301
#define WM_PASTE                        0x0302
#define WM_CLEAR                        0x0303
#define WM_UNDO                         0x0304
#define WM_RENDERFORMAT                 0x0305
#define WM_RENDERALLFORMATS             0x0306
#define WM_DESTROYCLIPBOARD             0x0307
#define WM_DRAWCLIPBOARD                0x0308
#define WM_PAINTCLIPBOARD               0x0309
#define WM_VSCROLLCLIPBOARD             0x030A
#define WM_SIZECLIPBOARD                0x030B
#define WM_ASKCBFORMATNAME              0x030C
#define WM_CHANGECBCHAIN                0x030D
#define WM_HSCROLLCLIPBOARD             0x030E
#define WM_QUERYNEWPALETTE              0x030F
#define WM_PALETTEISCHANGING            0x0310
#define WM_PALETTECHANGED               0x0311
#define WM_HOTKEY                       0x0312
#define WM_PRINT                        0x0317
#define WM_PRINTCLIENT                  0x0318
#define WM_APPCOMMAND                   0x0319
#define WM_THEMECHANGED                 0x031A
#define WM_HANDHELDFIRST                0x0358
#define WM_HANDHELDLAST                 0x035F
#define WM_AFXFIRST                     0x0360
#define WM_AFXLAST                      0x037F
#define WM_PENWINFIRST                  0x0380
#define WM_PENWINLAST                   0x038F
#define WM_USER                         0x0400
#define WM_APP                          0x8000

#define WMSZ_LEFT           1
#define WMSZ_RIGHT          2
#define WMSZ_TOP            3
#define WMSZ_TOPLEFT        4
#define WMSZ_TOPRIGHT       5
#define WMSZ_BOTTOM         6
#define WMSZ_BOTTOMLEFT     7
#define WMSZ_BOTTOMRIGHT    8

#define SWP_NOSIZE          0x0001
#define SWP_NOMOVE          0x0002
#define SWP_NOZORDER        0x0004
#define SWP_NOREDRAW        0x0008
#define SWP_NOACTIVATE      0x0010
#define SWP_FRAMECHANGED    0x0020  /* The frame changed: send WM_NCCALCSIZE */
#define SWP_SHOWWINDOW      0x0040
#define SWP_HIDEWINDOW      0x0080
#define SWP_NOCOPYBITS      0x0100
#define SWP_NOOWNERZORDER   0x0200  /* Don't do owner Z ordering */
#define SWP_NOSENDCHANGING  0x0400  /* Don't send WM_WINDOWPOSCHANGING */
#define SWP_DRAWFRAME       SWP_FRAMECHANGED
#define SWP_NOREPOSITION    SWP_NOOWNERZORDER
#define SWP_DEFERERASE      0x2000
#define SWP_ASYNCWINDOWPOS  0x4000

#define HWND_TOP        0
#define HWND_BOTTOM     1
#define HWND_TOPMOST    -1
#define HWND_NOTOPMOST  -2

#define SIZE_RESTORED       0
#define SIZE_MINIMIZED      1
#define SIZE_MAXIMIZED      2
#define SIZE_MAXSHOW        3
#define SIZE_MAXHIDE        4

#define MK_LBUTTON          0x0001
#define MK_RBUTTON          0x0002
#define MK_SHIFT            0x0004
#define MK_CONTROL          0x0008
#define MK_MBUTTON          0x0010
#define MK_XBUTTON1         0x0020
#define MK_XBUTTON2         0x0040

typedef struct tagTRACKMOUSEEVENT {
    DWORD cbSize;
    DWORD dwFlags;
    HWND  hwndTrack;
    DWORD dwHoverTime;
} TRACKMOUSEEVENT, *LPTRACKMOUSEEVENT;

WINUSERAPI
BOOL
WINAPI
TrackMouseEvent(
    __inout LPTRACKMOUSEEVENT lpEventTrack);

#define FVIRTKEY  TRUE          /* Assumed to be == TRUE */
#define FNOINVERT 0x02
#define FSHIFT    0x04
#define FCONTROL  0x08
#define FALT      0x10

#define FALSE 0
#define TRUE 1

#define SW_HIDE             0
#define SW_SHOWNORMAL       1
#define SW_NORMAL           1
#define SW_SHOWMINIMIZED    2
#define SW_SHOWMAXIMIZED    3
#define SW_MAXIMIZE         3
#define SW_SHOWNOACTIVATE   4
#define SW_SHOW             5
#define SW_MINIMIZE         6
#define SW_SHOWMINNOACTIVE  7
#define SW_SHOWNA           8
#define SW_RESTORE          9
#define SW_SHOWDEFAULT      10
#define SW_FORCEMINIMIZE    11
#define SW_MAX              11

#define CS_VREDRAW          0x0001
#define CS_HREDRAW          0x0002
#define CS_DBLCLKS          0x0008
#define CS_OWNDC            0x0020
#define CS_CLASSDC          0x0040
#define CS_PARENTDC         0x0080
#define CS_NOCLOSE          0x0200
#define CS_SAVEBITS         0x0800
#define CS_BYTEALIGNCLIENT  0x1000
#define CS_BYTEALIGNWINDOW  0x2000
#define CS_GLOBALCLASS      0x4000
#define CS_IME              0x00010000
#define CS_DROPSHADOW       0x00020000

#define MF_INSERT           0x00000000L
#define MF_CHANGE           0x00000080L
#define MF_APPEND           0x00000100L
#define MF_DELETE           0x00000200L
#define MF_REMOVE           0x00001000L
#define MF_BYCOMMAND        0x00000000L
#define MF_BYPOSITION       0x00000400L
#define MF_SEPARATOR        0x00000800L
#define MF_ENABLED          0x00000000L
#define MF_GRAYED           0x00000001L
#define MF_DISABLED         0x00000002L
#define MF_UNCHECKED        0x00000000L
#define MF_CHECKED          0x00000008L
#define MF_USECHECKBITMAPS  0x00000200L
#define MF_STRING           0x00000000L
#define MF_BITMAP           0x00000004L
#define MF_OWNERDRAW        0x00000100L
#define MF_POPUP            0x00000010L
#define MF_MENUBARBREAK     0x00000020L
#define MF_MENUBREAK        0x00000040L
#define MF_UNHILITE         0x00000000L
#define MF_HILITE           0x00000080L
#define MF_DEFAULT          0x00001000L
#define MF_SYSMENU          0x00002000L
#define MF_HELP             0x00004000L
#define MF_RIGHTJUSTIFY     0x00004000L
#define MF_MOUSESELECT      0x00008000L

#define IDI_APPLICATION     32512
#define IDI_HAND            32513
#define IDI_QUESTION        32514
#define IDI_EXCLAMATION     32515
#define IDI_ASTERISK        32516
#define IDI_WINLOGO         32517

#define MB_OK                       0x00000000L
#define MB_OKCANCEL                 0x00000001L
#define MB_ABORTRETRYIGNORE         0x00000002L
#define MB_YESNOCANCEL              0x00000003L
#define MB_YESNO                    0x00000004L
#define MB_RETRYCANCEL              0x00000005L
#define MB_CANCELTRYCONTINUE        0x00000006L
#define MB_ICONHAND                 0x00000010L
#define MB_ICONQUESTION             0x00000020L
#define MB_ICONEXCLAMATION          0x00000030L
#define MB_ICONASTERISK             0x00000040L
#define MB_USERICON                 0x00000080L
#define MB_ICONWARNING              MB_ICONEXCLAMATION
#define MB_ICONERROR                MB_ICONHAND
#define MB_ICONINFORMATION          MB_ICONASTERISK
#define MB_ICONSTOP                 MB_ICONHAND
#define MB_DEFBUTTON1               0x00000000L
#define MB_DEFBUTTON2               0x00000100L
#define MB_DEFBUTTON3               0x00000200L
#define MB_DEFBUTTON4               0x00000300L
#define MB_APPLMODAL                0x00000000L
#define MB_SYSTEMMODAL              0x00001000L
#define MB_TASKMODAL                0x00002000L
#define MB_HELP                     0x00004000L
#define MB_NOFOCUS                  0x00008000L
#define MB_SETFOREGROUND            0x00010000L
#define MB_DEFAULT_DESKTOP_ONLY     0x00020000L
#define MB_TOPMOST                  0x00040000L
#define MB_RIGHT                    0x00080000L
#define MB_RTLREADING               0x00100000L
#define MB_SERVICE_NOTIFICATION          0x00200000L
#define MB_SERVICE_NOTIFICATION_NT3X     0x00040000L

#define IDOK                1
#define IDCANCEL            2
#define IDABORT             3
#define IDRETRY             4
#define IDIGNORE            5
#define IDYES               6
#define IDNO                7
#define IDCLOSE         8
#define IDHELP          9
#define IDTRYAGAIN      10
#define IDCONTINUE      11
#define IDTIMEOUT 32000

#define PM_NOREMOVE     0
#define PM_REMOVE       1
#define PM_NOYIELD      2

#define IDC_ARROW           32512
#define IDC_IBEAM           32513
#define IDC_WAIT            32514
#define IDC_CROSS           32515
#define IDC_UPARROW         32516
#define IDC_SIZE            32640
#define IDC_ICON            32641
#define IDC_SIZENWSE        32642
#define IDC_SIZENESW        32643
#define IDC_SIZEWE          32644
#define IDC_SIZENS          32645
#define IDC_SIZEALL         32646
#define IDC_NO              32648
#define IDC_HAND            32649
#define IDC_APPSTARTING     32650
#define IDC_HELP            32651

#define WHITE_BRUSH         0
#define LTGRAY_BRUSH        1
#define GRAY_BRUSH          2
#define DKGRAY_BRUSH        3
#define BLACK_BRUSH         4
#define NULL_BRUSH          5
#define HOLLOW_BRUSH        NULL_BRUSH
#define WHITE_PEN           6
#define BLACK_PEN           7
#define NULL_PEN            8
#define OEM_FIXED_FONT      10
#define ANSI_FIXED_FONT     11
#define ANSI_VAR_FONT       12
#define SYSTEM_FONT         13
#define DEVICE_DEFAULT_FONT 14
#define DEFAULT_PALETTE     15
#define SYSTEM_FIXED_FONT   16
#define DEFAULT_GUI_FONT    17
#define DC_BRUSH            18
#define DC_PEN              19

#define VK_LBUTTON        0x01
#define VK_RBUTTON        0x02
#define VK_CANCEL         0x03
#define VK_MBUTTON        0x04
#define VK_XBUTTON1       0x05
#define VK_XBUTTON2       0x06
#define VK_BACK           0x08
#define VK_TAB            0x09
#define VK_CLEAR          0x0C
#define VK_RETURN         0x0D
#define VK_SHIFT          0x10
#define VK_CONTROL        0x11
#define VK_MENU           0x12
#define VK_PAUSE          0x13
#define VK_CAPITAL        0x14
#define VK_ESCAPE         0x1B
#define VK_CONVERT        0x1C
#define VK_NONCONVERT     0x1D
#define VK_ACCEPT         0x1E
#define VK_MODECHANGE     0x1F
#define VK_SPACE          0x20
#define VK_PRIOR          0x21
#define VK_NEXT           0x22
#define VK_END            0x23
#define VK_HOME           0x24
#define VK_LEFT           0x25
#define VK_UP             0x26
#define VK_RIGHT          0x27
#define VK_DOWN           0x28
#define VK_SELECT         0x29
#define VK_PRINT          0x2A
#define VK_EXECUTE        0x2B
#define VK_SNAPSHOT       0x2C
#define VK_INSERT         0x2D
#define VK_DELETE         0x2E
#define VK_HELP           0x2F
// VK_0 - VK_9 are the same as ASCII '0' - '9' (0x30 - 0x39)
// VK_A - VK_Z are the same as ASCII 'A' - 'Z' (0x41 - 0x5A)
#define VK_LWIN           0x5B
#define VK_RWIN           0x5C
#define VK_APPS           0x5D
#define VK_SLEEP          0x5F
#define VK_NUMPAD0        0x60
#define VK_NUMPAD1        0x61
#define VK_NUMPAD2        0x62
#define VK_NUMPAD3        0x63
#define VK_NUMPAD4        0x64
#define VK_NUMPAD5        0x65
#define VK_NUMPAD6        0x66
#define VK_NUMPAD7        0x67
#define VK_NUMPAD8        0x68
#define VK_NUMPAD9        0x69
#define VK_MULTIPLY       0x6A
#define VK_ADD            0x6B
#define VK_SEPARATOR      0x6C
#define VK_SUBTRACT       0x6D
#define VK_DECIMAL        0x6E
#define VK_DIVIDE         0x6F
#define VK_F1             0x70
#define VK_F2             0x71
#define VK_F3             0x72
#define VK_F4             0x73
#define VK_F5             0x74
#define VK_F6             0x75
#define VK_F7             0x76
#define VK_F8             0x77
#define VK_F9             0x78
#define VK_F10            0x79
#define VK_F11            0x7A
#define VK_F12            0x7B
#define VK_F13            0x7C
#define VK_F14            0x7D
#define VK_F15            0x7E
#define VK_F16            0x7F
#define VK_F17            0x80
#define VK_F18            0x81
#define VK_F19            0x82
#define VK_F20            0x83
#define VK_F21            0x84
#define VK_F22            0x85
#define VK_F23            0x86
#define VK_F24            0x87

#define QS_KEY              0x0001
#define QS_MOUSEMOVE        0x0002
#define QS_MOUSEBUTTON      0x0004
#define QS_POSTMESSAGE      0x0008
#define QS_TIMER            0x0010
#define QS_PAINT            0x0020
#define QS_SENDMESSAGE      0x0040
#define QS_HOTKEY           0x0080
#define QS_ALLPOSTMESSAGE   0x0100
#define QS_RAWINPUT         0x0400
#define QS_MOUSE           (QS_MOUSEMOVE | QS_MOUSEBUTTON)
#define QS_INPUT           (QS_MOUSE | QS_KEY | QS_RAWINPUT)
#define QS_ALLEVENTS       (QS_INPUT | QS_POSTMESSAGE | QS_TIMER | QS_PAINT | QS_HOTKEY)
#define QS_ALLINPUT        (QS_ALLEVENTS | QS_SENDMESSAGE)

#define WAIT_TIMEOUT        258L

#define CF_TEXT             1
#define CF_BITMAP           2
#define CF_METAFILEPICT     3
#define CF_SYLK             4
#define CF_DIF              5
#define CF_TIFF             6
#define CF_OEMTEXT          7
#define CF_DIB              8
#define CF_PALETTE          9
#define CF_PENDATA          10
#define CF_RIFF             11
#define CF_WAVE             12
#define CF_UNICODETEXT      13
#define CF_ENHMETAFILE      14
#define CF_HDROP            15
#define CF_LOCALE           16
#define CF_DIBV5            17

#define COLOR_SCROLLBAR         0
#define COLOR_BACKGROUND        1
#define COLOR_ACTIVECAPTION     2
#define COLOR_INACTIVECAPTION   3
#define COLOR_MENU              4
#define COLOR_WINDOW            5
#define COLOR_WINDOWFRAME       6
#define COLOR_MENUTEXT          7
#define COLOR_WINDOWTEXT        8
#define COLOR_CAPTIONTEXT       9
#define COLOR_ACTIVEBORDER      10
#define COLOR_INACTIVEBORDER    11
#define COLOR_APPWORKSPACE      12
#define COLOR_HIGHLIGHT         13
#define COLOR_HIGHLIGHTTEXT     14
#define COLOR_BTNFACE           15
#define COLOR_BTNSHADOW         16
#define COLOR_GRAYTEXT          17
#define COLOR_BTNTEXT           18
#define COLOR_INACTIVECAPTIONTEXT 19
#define COLOR_BTNHIGHLIGHT      20
#define COLOR_3DDKSHADOW        21
#define COLOR_3DLIGHT           22
#define COLOR_INFOTEXT          23
#define COLOR_INFOBK            24
#define COLOR_HOTLIGHT          26
#define COLOR_GRADIENTACTIVECAPTION 27
#define COLOR_GRADIENTINACTIVECAPTION 28
#define COLOR_MENUHILIGHT       29
#define COLOR_MENUBAR           30
#define COLOR_DESKTOP           COLOR_BACKGROUND
#define COLOR_3DFACE            COLOR_BTNFACE
#define COLOR_3DSHADOW          COLOR_BTNSHADOW
#define COLOR_3DHIGHLIGHT       COLOR_BTNHIGHLIGHT
#define COLOR_3DHILIGHT         COLOR_BTNHIGHLIGHT
#define COLOR_BTNHILIGHT        COLOR_BTNHIGHLIGHT


WINUSERAPI DWORD WINAPI GetSysColor(__in int nIndex);


WINUSERAPI
int
WINAPI
GetSystemMetrics(
    __in int nIndex);

typedef struct tagMSG {
    HWND hwnd;
    UINT message;
    WPARAM wParam;
    LPARAM lParam;
    DWORD time;
    POINT pt;
} MSG, *PMSG, *LPMSG;

WINUSERAPI
BOOL
WINAPI
GetMessageA(
    __out LPMSG lpMsg,
    __in_opt HWND hWnd,
    __in UINT wMsgFilterMin,
    __in UINT wMsgFilterMax);
WINUSERAPI
BOOL
WINAPI
PeekMessageA(
    __out LPMSG lpMsg,
    __in_opt HWND hWnd,
    __in UINT wMsgFilterMin,
    __in UINT wMsgFilterMax,
    __in UINT wRemoveMsg);
WINUSERAPI
BOOL
WINAPI
TranslateMessage(
    __in CONST MSG *lpMsg);
WINUSERAPI
LRESULT
WINAPI
DispatchMessageA(
    __in CONST MSG *lpMsg);
#define MOD_ALT         0x0001
#define MOD_CONTROL     0x0002
#define MOD_SHIFT       0x0004
#define MOD_WIN         0x0008
WINUSERAPI
LRESULT
WINAPI
SendMessageA(
    __in HWND hWnd,
    __in UINT Msg,
    __in WPARAM wParam,
    __in LPARAM lParam);
WINUSERAPI
BOOL
WINAPI
PostMessageA(
    __in_opt HWND hWnd,
    __in UINT Msg,
    __in WPARAM wParam,
    __in LPARAM lParam);
WINUSERAPI
LRESULT
WINAPI
DefWindowProcA(
    __in HWND hWnd,
    __in UINT Msg,
    __in WPARAM wParam,
    __in LPARAM lParam);
WINUSERAPI
VOID
WINAPI
PostQuitMessage(
    __in int nExitCode);
WINUSERAPI
DWORD
WINAPI
MsgWaitForMultipleObjects(
    __in DWORD nCount,
    __in_opt CONST HANDLE *pHandles,
    __in BOOL fWaitAll,
    __in DWORD dwMilliseconds,
    __in DWORD dwWakeMask);
WINUSERAPI DWORD WINAPI GetKeyState(__in int nVirtKey);

WINUSERAPI BOOL WINAPI OpenClipboard(__in_opt HWND hWndNewOwner);
WINUSERAPI BOOL WINAPI CloseClipboard(VOID);
WINUSERAPI HANDLE WINAPI SetClipboardData(__in UINT uFormat, __in_opt HANDLE hMem);
WINUSERAPI HANDLE WINAPI GetClipboardData(__in UINT uFormat);
WINUSERAPI BOOL WINAPI EmptyClipboard(VOID);

#define GMEM_FIXED          0x0000
#define GMEM_MOVEABLE       0x0002
#define GMEM_NOCOMPACT      0x0010
#define GMEM_NODISCARD      0x0020
#define GMEM_ZEROINIT       0x0040
#define GMEM_MODIFY         0x0080
#define GMEM_DISCARDABLE    0x0100
#define GMEM_NOT_BANKED     0x1000
#define GMEM_SHARE          0x2000
#define GMEM_DDESHARE       0x2000
#define GMEM_NOTIFY         0x4000
#define GMEM_LOWER          GMEM_NOT_BANKED
#define GMEM_INVALID_HANDLE 0x8000
HANDLE WINAPI GlobalAlloc(__in UINT uFlags, __in DWORD dwBytes);
DWORD WINAPI GlobalSize(__in HANDLE hMem);
LPVOID WINAPI GlobalLock(__in HANDLE hMem);
BOOL WINAPI GlobalUnlock(__in HANDLE hMem);
HANDLE WINAPI GlobalFree(HANDLE hMem);

typedef __stdcall LRESULT (*WNDPROC)(HWND, UINT, WPARAM, LPARAM);
typedef struct tagWNDCLASSEXA {
  UINT cbSize;
  UINT style;
  WNDPROC lpfnWndProc;
  int cbClsExtra;
  int cbWndExtra;
  HINSTANCE hInstance;
  HICON hIcon;
  HCURSOR hCursor;
  HBRUSH hbrBackground;
  LPCSTR lpszMenuName;
  LPCSTR lpszClassName;
  HICON hIconSm;
} WNDCLASSEXA;
WINUSERAPI
ATOM
WINAPI
RegisterClassExA(
    __in CONST WNDCLASSEXA *);
WINUSERAPI
HWND
WINAPI
CreateWindowExA(
    __in DWORD dwExStyle,
    __in_opt LPCSTR lpClassName,
    __in_opt LPCSTR lpWindowName,
    __in DWORD dwStyle,
    __in int X,
    __in int Y,
    __in int nWidth,
    __in int nHeight,
    __in_opt HWND hWndParent,
    __in_opt HMENU hMenu,
    __in_opt HINSTANCE hInstance,
    __in_opt LPVOID lpParam);
WINUSERAPI
BOOL
WINAPI
DestroyWindow(
    __in HWND hWnd);
WINUSERAPI
BOOL
WINAPI
ShowWindow(
    __in HWND hWnd,
    __in int nCmdShow);
WINUSERAPI
BOOL
WINAPI
CloseWindow(
    __in  HWND hWnd);
WINUSERAPI
BOOL
WINAPI
MoveWindow(
    __in HWND hWnd,
    __in int X,
    __in int Y,
    __in int nWidth,
    __in int nHeight,
    __in BOOL bRepaint);
WINUSERAPI
BOOL
WINAPI
SetWindowPos(
    __in HWND hWnd,
    __in_opt HWND hWndInsertAfter,
    __in int X,
    __in int Y,
    __in int cx,
    __in int cy,
    __in UINT uFlags);
#define SRCCOPY             (DWORD)0x00CC0020 /* dest = source                   */
#define SRCPAINT            (DWORD)0x00EE0086 /* dest = source OR dest           */
#define SRCAND              (DWORD)0x008800C6 /* dest = source AND dest          */
#define SRCINVERT           (DWORD)0x00660046 /* dest = source XOR dest          */
#define SRCERASE            (DWORD)0x00440328 /* dest = source AND (NOT dest )   */
#define NOTSRCCOPY          (DWORD)0x00330008 /* dest = (NOT source)             */
#define NOTSRCERASE         (DWORD)0x001100A6 /* dest = (NOT src) AND (NOT dest) */
#define MERGECOPY           (DWORD)0x00C000CA /* dest = (source AND pattern)     */
#define MERGEPAINT          (DWORD)0x00BB0226 /* dest = (NOT source) OR dest     */
#define PATCOPY             (DWORD)0x00F00021 /* dest = pattern                  */
#define PATPAINT            (DWORD)0x00FB0A09 /* dest = DPSnoo                   */
#define PATINVERT           (DWORD)0x005A0049 /* dest = pattern XOR dest         */
#define DSTINVERT           (DWORD)0x00550009 /* dest = (NOT dest)               */
#define BLACKNESS           (DWORD)0x00000042 /* dest = BLACK                    */
#define WHITENESS           (DWORD)0x00FF0062 /* dest = WHITE                    */
#define NOMIRRORBITMAP      (DWORD)0x80000000 /* Do not Mirror the bitmap in this call */
#define CAPTUREBLT          (DWORD)0x40000000 /* Include layered windows */
BOOL    WINAPI BitBlt(__in HDC hdcDst, __in int x, __in int y, __in int cx, __in int cy, __in_opt HDC hdcSrc, __in int x1, __in int y1, __in DWORD rop);
HBITMAP WINAPI CreateCompatibleBitmap(__in HDC hdc, __in int cx, __in int cy);
HDC     WINAPI CreateCompatibleDC(__in_opt HDC hdc);
BOOL    WINAPI DeleteDC(__in HDC hdc);
HDC     WINAPI GetDC(__in_opt HWND hWnd);
int     WINAPI ReleaseDC(__in_opt HWND hWnd, __in HDC hDC);
BOOL
WINAPI
GetTextExtentPoint32A(
  __in HDC hdc,
  __in_ecount(c) LPCSTR lpString,
  __in int c,
  __out LPPOINT lpsz);

typedef struct tagRECT {
    LONG left;
    LONG top;
    LONG right;
    LONG bottom;
} RECT, *LPRECT;

#define TPM_LEFTBUTTON  0x0000L
#define TPM_RIGHTBUTTON 0x0002L
#define TPM_LEFTALIGN   0x0000L
#define TPM_CENTERALIGN 0x0004L
#define TPM_RIGHTALIGN  0x0008L
#define TPM_TOPALIGN        0x0000L
#define TPM_VCENTERALIGN    0x0010L
#define TPM_BOTTOMALIGN     0x0020L
#define TPM_HORIZONTAL      0x0000L
#define TPM_VERTICAL        0x0040L
#define TPM_NONOTIFY        0x0080L
#define TPM_RETURNCMD       0x0100L
#define TPM_RECURSE         0x0001L
#define TPM_HORPOSANIMATION 0x0400L
#define TPM_HORNEGANIMATION 0x0800L
#define TPM_VERPOSANIMATION 0x1000L
#define TPM_VERNEGANIMATION 0x2000L
#define TPM_NOANIMATION     0x4000L
#define TPM_LAYOUTRTL       0x8000L
WINUSERAPI
BOOL
WINAPI
SetMenu(
    __in HWND hWnd,
    __in_opt HMENU hMenu);
WINUSERAPI
HMENU
WINAPI
CreateMenu(VOID);
WINUSERAPI
HMENU
WINAPI
CreatePopupMenu(VOID);
WINUSERAPI
BOOL
WINAPI
DestroyMenu(
    __in HMENU hMenu);
WINUSERAPI
BOOL
WINAPI
TrackPopupMenu(
    __in HMENU hMenu,
    __in UINT uFlags,
    __in int x,
    __in int y,
    __in int nReserved,
    __in HWND hWnd,
    __in_opt CONST RECT *prcRect);
WINUSERAPI
DWORD
WINAPI
CheckMenuItem(
    __in HMENU hMenu,
    __in UINT uIDCheckItem,
    __in UINT uCheck);
WINUSERAPI
BOOL
WINAPI
AppendMenuA(
    __in HMENU hMenu,
    __in UINT uFlags,
    __in UINT_PTR uIDNewItem,
    __in_opt LPCSTR lpNewItem);

#define TRANSPARENT 1
#define OPAQUE      2
int WINAPI SetBkMode(__in HDC hdc, __in int mode);

WINUSERAPI
int
WINAPI
DrawTextA(
    __in HDC hdc,
    __inout_ecount(cchText) LPCSTR lpchText,
    __in int cchText,
    __inout LPRECT lprc,
    __in UINT format);

typedef struct tagPAINTSTRUCT {
    HDC         hdc;
    BOOL        fErase;
    RECT        rcPaint;
    BOOL        fRestore;
    BOOL        fIncUpdate;
    BYTE        rgbReserved[32];
} PAINTSTRUCT, *LPPAINTSTRUCT;
WINUSERAPI
HDC
WINAPI
BeginPaint(
    __in HWND hWnd,
    __out LPPAINTSTRUCT lpPaint);
WINUSERAPI
BOOL
WINAPI
EndPaint(
    __in HWND hWnd,
    __in CONST PAINTSTRUCT *lpPaint);
WINUSERAPI
BOOL
WINAPI
InvalidateRect(
    __in_opt HWND hWnd,
    __in_opt CONST RECT *lpRect,
    __in BOOL bErase);
WINUSERAPI
BOOL
WINAPI
SetWindowTextA(
    __in HWND hWnd,
    __in_opt LPCSTR lpString);
WINUSERAPI
int
WINAPI
GetWindowTextA(
    __in HWND hWnd,
    __out_ecount(nMaxCount) LPSTR lpString,
    __in int nMaxCount);
WINUSERAPI
int
WINAPI
MessageBoxA(
    __in_opt HWND hWnd,
    __in_opt LPCSTR lpText,
    __in_opt LPCSTR lpCaption,
    __in UINT uType);

WINUSERAPI
HICON
WINAPI
LoadIconA(
    __in_opt HINSTANCE hInstance,
    __in LPCSTR lpIconName);
WINUSERAPI
HCURSOR
WINAPI
LoadCursorA(
    __in_opt HINSTANCE hInstance,
    __in LPCSTR lpCursorName);
WINAPI PVOID GetStockObject(__in int i);
WINUSERAPI
BOOL
WINAPI
UpdateWindow(
    __in HWND hWnd);
WINUSERAPI
BOOL
WINAPI
ClientToScreen(
    __in HWND hWnd,
    __inout LPPOINT pt);
WINUSERAPI
BOOL
WINAPI
ScreenToClient(
    __in HWND hWnd,
    __inout LPPOINT pt);
WINUSERAPI
BOOL
WINAPI
GetClientRect(
    __in HWND hWnd,
    __out LPRECT lpRect);
WINUSERAPI
BOOL
WINAPI
GetWindowRect(
    __in HWND hWnd,
    __out LPRECT lpRect);
WINUSERAPI
BOOL
WINAPI
AdjustWindowRect(
    __inout LPRECT lpRect,
    __in DWORD dwStyle,
    __in BOOL bMenu);
WINUSERAPI
BOOL
WINAPI
AdjustWindowRectEx(
    __inout LPRECT lpRect,
    __in DWORD dwStyle,
    __in BOOL bMenu,
    __in DWORD dwExStyle);
#define PS_SOLID            0
#define PS_DASH             1       /* -------  */
#define PS_DOT              2       /* .......  */
#define PS_DASHDOT          3       /* _._._._  */
#define PS_DASHDOTDOT       4       /* _.._.._  */
#define PS_NULL             5
#define PS_INSIDEFRAME      6
#define PS_USERSTYLE        7
#define PS_ALTERNATE        8
DWORD WINAPI SetTextColor(__in HDC hdc, __in DWORD color);
BOOL WINAPI TextOutA( __in HDC hdc, __in int x, __in int y, __in_ecount(c) LPCSTR lpString, __in int c);
BOOL WINAPI MoveToEx( __in HDC hdc, __in int x, __in int y, __out_opt LPPOINT lppt);
BOOL WINAPI LineTo( __in HDC hdc, __in int x, __in int y);
BOOL WINAPI Rectangle(__in HDC hdc, __in int left, __in int top, __in int right, __in int bottom);
HANDLE WINAPI SelectObject(__in HDC hdc, __in HANDLE h);
BOOL WINAPI DeleteObject(__in HANDLE ho);
DWORD WINAPI SetBkColor(__in HDC hdc, __in DWORD color);
HANDLE WINAPI CreateSolidBrush(__in DWORD color);
//DWORD WINAPI SetDCBrushColor(__in HDC hdc, __in DWORD color);
HANDLE WINAPI CreatePen(__in int style, __in int width, __in DWORD color);
//DWORD WINAPI SetDCPenColor(__in HDC hdc, __in DWORD color);
int WINAPI FillRect(__in HDC hDC, __in CONST RECT *lprc, __in HBRUSH hbr);

WINUSERAPI HWND WINAPI GetCapture(VOID);
WINUSERAPI HWND WINAPI SetCapture(__in HWND hWnd);
WINUSERAPI BOOL WINAPI ReleaseCapture(VOID);

#define FORMAT_MESSAGE_ALLOCATE_BUFFER 0x00000100
#define FORMAT_MESSAGE_IGNORE_INSERTS  0x00000200
#define FORMAT_MESSAGE_FROM_STRING     0x00000400
#define FORMAT_MESSAGE_FROM_HMODULE    0x00000800
#define FORMAT_MESSAGE_FROM_SYSTEM     0x00001000
#define FORMAT_MESSAGE_ARGUMENT_ARRAY  0x00002000
#define FORMAT_MESSAGE_MAX_WIDTH_MASK  0x000000FF

DWORD
WINAPI
GetLastError(VOID);
VOID
WINAPI
SetLastError(
    __in DWORD dwErrCode
    );
DWORD
WINAPI
FormatMessageA(
    DWORD dwFlags,
    LPVOID lpSource,
    DWORD dwMessageId,
    DWORD dwLanguageId,
    LPSTR lpBuffer,
    DWORD nSize,
    void *Arguments
    );

#define OFN_READONLY                 0x00000001
#define OFN_OVERWRITEPROMPT          0x00000002
#define OFN_HIDEREADONLY             0x00000004
#define OFN_NOCHANGEDIR              0x00000008
#define OFN_SHOWHELP                 0x00000010
#define OFN_ENABLEHOOK               0x00000020
#define OFN_ENABLETEMPLATE           0x00000040
#define OFN_ENABLETEMPLATEHANDLE     0x00000080
#define OFN_NOVALIDATE               0x00000100
#define OFN_ALLOWMULTISELECT         0x00000200
#define OFN_EXTENSIONDIFFERENT       0x00000400
#define OFN_PATHMUSTEXIST            0x00000800
#define OFN_FILEMUSTEXIST            0x00001000
#define OFN_CREATEPROMPT             0x00002000
#define OFN_SHAREAWARE               0x00004000
#define OFN_NOREADONLYRETURN         0x00008000
#define OFN_NOTESTFILECREATE         0x00010000
#define OFN_NONETWORKBUTTON          0x00020000
#define OFN_NOLONGNAMES              0x00040000     // force no long names for 4.x modules
#define OFN_EXPLORER                 0x00080000     // new look commdlg
#define OFN_NODEREFERENCELINKS       0x00100000
#define OFN_LONGNAMES                0x00200000     // force long names for 3.x modules
#define OFN_ENABLEINCLUDENOTIFY      0x00400000     // send include message to callback
#define OFN_ENABLESIZING             0x00800000
#define OFN_DONTADDTORECENT          0x02000000
#define OFN_FORCESHOWHIDDEN          0x10000000    // Show All files including System and hidden files
typedef struct tagOFNA {
   DWORD        lStructSize;
   HWND         hwndOwner;
   HINSTANCE    hInstance;
   LPCSTR       lpstrFilter;
   LPSTR        lpstrCustomFilter;
   DWORD        nMaxCustFilter;
   DWORD        nFilterIndex;
   LPSTR        lpstrFile;
   DWORD        nMaxFile;
   LPSTR        lpstrFileTitle;
   DWORD        nMaxFileTitle;
   LPCSTR       lpstrInitialDir;
   LPCSTR       lpstrTitle;
   DWORD        Flags;
   WORD         nFileOffset;
   WORD         nFileExtension;
   LPCSTR       lpstrDefExt;
   LPARAM       lCustData;
   LPVOID       lpfnHook;
   LPCSTR       lpTemplateName;
   //void *       pvReserved;	// undef for win98 compat
   //DWORD        dwReserved;
   //DWORD        FlagsEx;
} OPENFILENAMEA, *LPOPENFILENAMEA;
BOOL WINAPI GetOpenFileNameA(LPOPENFILENAMEA);
BOOL WINAPI GetSaveFileNameA(LPOPENFILENAMEA);

#define SB_HORZ             0
#define SB_VERT             1
#define SB_CTL              2
#define SB_BOTH             3

#define SB_LINEUP           0
#define SB_LINELEFT         0
#define SB_LINEDOWN         1
#define SB_LINERIGHT        1
#define SB_PAGEUP           2
#define SB_PAGELEFT         2
#define SB_PAGEDOWN         3
#define SB_PAGERIGHT        3
#define SB_THUMBPOSITION    4
#define SB_THUMBTRACK       5
#define SB_TOP              6
#define SB_LEFT             6
#define SB_BOTTOM           7
#define SB_RIGHT            7
#define SB_ENDSCROLL        8

#define SIF_RANGE           0x0001
#define SIF_PAGE            0x0002
#define SIF_POS             0x0004
#define SIF_DISABLENOSCROLL 0x0008
#define SIF_TRACKPOS        0x0010
#define SIF_ALL             (SIF_RANGE | SIF_PAGE | SIF_POS | SIF_TRACKPOS)

WINUSERAPI
int
WINAPI
SetScrollPos(
    __in HWND hWnd,
    __in int nBar,
    __in int nPos,
    __in BOOL bRedraw);

WINUSERAPI
int
WINAPI
GetScrollPos(
    __in HWND hWnd,
    __in int nBar);

typedef struct tagSCROLLINFO
{
    UINT    cbSize;
    UINT    fMask;
    int     nMin;
    int     nMax;
    UINT    nPage;
    int     nPos;
    int     nTrackPos;
}   SCROLLINFO, *LPSCROLLINFO;
typedef SCROLLINFO CONST *LPCSCROLLINFO;

WINUSERAPI
int
WINAPI
SetScrollInfo(
    __in HWND hwnd,
    __in int nBar,
    __in LPCSCROLLINFO lpsi,
    __in BOOL redraw);

WINUSERAPI
BOOL
WINAPI
GetScrollInfo(
    __in HWND hwnd,
    __in int nBar,
    __inout LPSCROLLINFO lpsi);
EOS

  new_api_c <<EOS, 'shell32'
typedef HANDLE HDROP;
WINAPI UINT DragQueryFileA(HDROP,UINT,LPSTR,UINT);
WINAPI BOOL DragQueryPoint(HDROP,LPPOINT);
WINAPI void DragFinish(HDROP);
WINAPI void DragAcceptFiles(HWND,BOOL);
EOS

def self.last_error_msg(errno = getlasterror)
  message = ' '*512
  if formatmessagea(FORMAT_MESSAGE_FROM_SYSTEM, nil, errno, 0, message, message.length, nil) == 0
    message = 'unknown error %x' % errno
  else
    message = message[0, message.index(?\0)] if message.index(?\0)
    message.chomp!
  end
  message
end

def self.setdcbrushcolor(hdc, col)
  @@brushes ||= {}
  b = @@brushes[col] ||= createsolidbrush(col)
  selectobject(hdc, b)
end
def self.setdcpencolor(hdc, col)
  @@pens ||= {}
  p = @@pens[col] ||= createpen(PS_SOLID, 0, col)
  selectobject(hdc, p)
end
end

module Protect
  @@lasterror = Time.now
  def protect
    yield
  rescue Object
    puts $!.message, $!.backtrace   # also dump on stdout, for c/c
    delay = Time.now-@@lasterror
    sleep 1-delay if delay < 1      # msgbox flood protection
    @@lasterror = Time.now
    messagebox([$!.message, $!.backtrace].join("\n"), $!.class.name)
  end
end

module Msgbox
  include Protect

  def toplevel
    p = self
    p = p.parent while p.respond_to? :parent and p.parent
    p
  end

  # shows a message box (non-modal)
  # args: message, title/optionhash
  def messagebox(*a)
    MessageBox.new(toplevel, *a)
  end

  # asks for user input, yields the result (unless 'cancel' clicked)
  # args: prompt, :text => default text, :title => title
  def inputbox(*a)
    InputBox.new(toplevel, *a) { |*ya| protect { yield(*ya) } }
  end

  # asks to chose a file to open, yields filename
  # args: title, :path => path
  def openfile(*a)
    OpenFile.new(toplevel, *a) { |*ya| protect { yield(*ya) } }
  end

  # same as openfile, but for writing a (new) file
  def savefile(*a)
    SaveFile.new(toplevel, *a) { |*ya| protect { yield(*ya) } }
  end

  # displays a popup showing a table, yields the selected row
  # args: title, [[col0 title, col1 title...], [col0 val0, col1 val0...], [val1], [val2]...]
  def listwindow(*a)
    ListWindow.new(toplevel, *a) { |*ya| protect { yield(*ya) } }
  end
end

class WinWidget
  include Msgbox
  attr_accessor :parent, :hwnd, :x, :y, :width, :height

  def initialize
    @parent = nil
    @hwnd = nil
    @x = @y = @width = @height = 0
  end

  def grab_focus
    return if not @parent
    @parent.set_focus(self) if @parent.respond_to? :set_focus
  end

  def focus?
    return true if not @parent
    (@parent.respond_to?(:focus?) ? @parent.focus? : true) and
    (@parent.respond_to?(:has_focus?) ? @parent.has_focus?(self) : true)
  end

  def redraw
    invalidate(0, 0, @width, @height)
  end

  def invalidate(x, y, w, h)
    x += @x
    y += @y
    rect = Win32Gui.alloc_c_struct('RECT', :left => x, :right => x+w, :top => y, :bottom => y+h)
    Win32Gui.invalidaterect(@hwnd, rect, Win32Gui::FALSE)
  end
end

class ContainerChoiceWidget < WinWidget
  attr_accessor :views, :view_indexes
  def initialize(*a, &b)
    @views = {}
    @view_indexes = []
    @curview = nil
    @visible = false

    super()

    initialize_widget(*a, &b)
  end

  def initialize_visible_
    @visible = true
    @views.each { |k, v| v.initialize_visible_ }
  end

  def view(i)
    @views[i]
  end

  def showview(i)
    @curview = @views[i]
    @curview.redraw if @curview
  end

  def addview(name, w)
    @view_indexes << name
    @views[name] = w
    @curview ||= w
    w.parent = self
    w.hwnd = @hwnd
    w.x, w.y, w.width, w.height = @x, @y, @width, @height
    w.initialize_visible_ if @visible
    w
  end

  def curview
    @curview
  end

  def curview_index
    @views.index(@curview)
  end

  %w[click click_ctrl mouserelease mousemove rightclick doubleclick mouse_wheel mouse_wheel_ctrl keypress_ keypress_ctrl_].each { |m|
    define_method(m) { |*a| @curview.send(m, *a) if @curview and @curview.respond_to? m }
  }

  def paint_(rc)
    @curview.paint_(rc) if @curview
  end

  def resized_(w, h)
    @width = w
    @height = h
    @views.each { |k, v|
      v.x = @x
      v.y = @y
      v.resized_(w, h)
    }
  end

  def hwnd=(h)
    @hwnd = h
    @views.each { |k, v| v.hwnd = h }
  end

  def has_focus?(c)
    c == @curview
  end

  def set_focus(c)
    @curview = c
    grab_focus
    redraw
  end
end

class ContainerVBoxWidget < WinWidget
  def initialize(*a, &b)
    @views = []
    @focus_idx = 0
    @visible = false
    @wantheight = {}
    @spacing = 3
    @resizing = nil

    super()

    initialize_widget(*a, &b)
  end

  def initialize_visible_
    @visible = true
    @views.each { |v| v.initialize_visible_ }
  end

  def add(w, opts={})
    @views << w
    w.parent = self
    w.hwnd = @hwnd
    resized_(@width, @height)
    w.initialize_visible_ if @visible
  end

  def click(x, y)
    cy = 0
    pv = []
    @views.each_with_index { |v, i|
      if y >= cy+1 and y < cy + v.height - 1
        if @focus_idx != i
          @focus_idx = i
          redraw
        end
        v.click(x, y-v.y) if v.respond_to? :click
        return
      end
      cy += v.height
      if y >= cy-1 and y < cy+@spacing+1
        @resizing = v
        @wantheight[@resizing] ||= v.height
        @tmpwantheight = []
        pv.each { |vv| @tmpwantheight << vv if not @wantheight[vv] ; @wantheight[vv] ||= vv.height }
        return
      end
      cy += @spacing
      pv << v
    }
  end

  def mousemove(x, y)
    if @resizing
      @wantheight[@resizing] = [0, y - @resizing.y].max
      resized_(@width, @height)
    elsif v = @views[@focus_idx]
      v.mousemove(x, y-v.y) if v.respond_to? :mousemove
    end
  end

  def mouserelease(x, y)
    if @resizing
      @wantheight[@resizing] = [0, y - @resizing.y].max
      @resizing = nil
      @tmpwantheight.each { |vv| @wantheight.delete vv }
      @tmpwantheight = nil
      resized_(@width, @height)
    elsif v = @views[@focus_idx]
      v.mouserelease(x, y-v.y) if v.respond_to? :mouserelease
    end
  end

  %w[click_ctrl rightclick doubleclick].each { |m|
    define_method(m) { |x, y|
      if v = find_view_y(y, true)
        v.send(m, x, y-v.y) if v.respond_to? m
      end
    }
  }

  %w[mouse_wheel mouse_wheel_ctrl].each { |m|
    define_method(m) { |d, x, y|
      if v = find_view_y(y, false)
        v.send(m, d, x, y-v.y) if v.respond_to? m
      end
    }
  }
  %w[keypress_ keypress_ctrl_].each { |m|
    define_method(m) { |k|
      if v = @views[@focus_idx] and v.respond_to? m
        v.send(m, k)
      end
    }
  }

  def paint_(hdc)
    # TODO check invalidated rectangle
    x = @x
    y = @y
    Win32Gui.selectobject(hdc, Win32Gui.getstockobject(Win32Gui::DC_BRUSH))
    Win32Gui.selectobject(hdc, Win32Gui.getstockobject(Win32Gui::DC_PEN))
    col = Win32Gui.getsyscolor(Win32Gui::COLOR_BTNFACE)
    Win32Gui.setdcbrushcolor(hdc, col)
    Win32Gui.setdcpencolor(hdc, col)
    @views.each { |v|
      v.paint_(hdc) if v.height > 0
      y += v.height
      Win32Gui.rectangle(hdc, x, y, x+@width, y+@spacing)
      y += @spacing
    }
    Win32Gui.rectangle(hdc, x, y, x+@width, y+@height)
  end

  def resized_(w, h)
    @width = w
    @height = h
    x = @x
    y = @y
    freesize = h
    freesize -= @spacing*(@views.length-1)
    nrfree = 0
    @views.each { |v|
      if @wantheight[v]
        freesize -= @wantheight[v]
      else
        nrfree += 1
      end
    }
    freesize = 0 if freesize < 0
    @views.each { |v|
      v.x = x
      v.y = y
      ch = @wantheight[v] || freesize/nrfree
      v.resized_(w, ch)
      y += ch + @spacing
    }
    redraw
  end

  def find_view_y(ty, update_focus=false)
    y = 0
    @views.each_with_index { |v, i|
      if ty >= y and ty < y + v.height
        if update_focus and @focus_idx != i
          @focus_idx = i
          redraw
        end
        return v
      end
      y += v.height + @spacing
    }
    nil
  end

  def hwnd=(h)
    @hwnd = h
    @views.each { |v| v.hwnd = h }
  end

  def resize_child(cld, w, h)
    return if @wantheight[cld] == h
    if h < 0
      @wantheight.delete cld
    else
      @wantheight[cld] = h
    end
    resized_(@width, @height)
  end

  def has_focus?(c)
    c == @views[@focus_idx]
  end

  def set_focus(c)
    @focus_idx = @views.index(c)
    grab_focus
    redraw
  end
end

module TextWidget
  attr_accessor :caret_x, :caret_y, :hl_word, :hl_word_re, :font_width, :font_height

  def initialize_text
    @caret_x = @caret_y = 0		# text cursor position
    @oldcaret_x = @oldcaret_y = 1
    @font_width = @font_height = 1
    @hl_word = nil
  end

  def update_hl_word(line, offset, mode=:asm)
    return if not line
    word = line[0...offset].to_s[/\w*$/] << line[offset..-1].to_s[/^\w*/]
    word = nil if word == ''
    if @hl_word != word
      if word
        if mode == :asm and defined?(@dasm) and @dasm
          re = @dasm.gui_hilight_word_regexp(word)
        else
          re = Regexp.escape(word)
        end
        @hl_word_re = /^(.*?)(\b(?:#{re})\b)/
      end
      @hl_word = word
    end
  end

  def set_caret_from_click(x, y)
    @caret_x = (x-1).to_i / @font_width
    @caret_y = y.to_i / @font_height
    update_caret
  end

  def invalidate_caret(cx, cy, x=0, y=0)
    invalidate(x + cx*@font_width, y + cy*@font_height, 2, @font_height)
  end

  def clipboard_copy(buf)
    Win32Gui.openclipboard(@hwnd)
    Win32Gui.emptyclipboard
    if buf and not buf.empty?
      h = Win32Gui.globalalloc(Win32Gui::GMEM_MOVEABLE, buf.length+1)
      ptr = Win32Gui.globallock(h)
      Win32Gui.memory_write(ptr, buf)
      Win32Gui.globalunlock(h)
      Win32Gui.setclipboarddata(Win32Gui::CF_TEXT, h)
      # on(WM_DESTROYCLIPBOARD) { Win32Gui.globalfree(h) }
    end
    Win32Gui.closeclipboard
  end

  def clipboard_paste
    Win32Gui.openclipboard(@hwnd)
    h = Win32Gui.getclipboarddata(Win32Gui::CF_TEXT)
    if h and h != 0 and h != Win32Gui::GMEM_INVALID_HANDLE
      sz = Win32Gui.globalsize(h)
      ptr = Win32Gui.globallock(h)
      buf = Win32Gui.memory_read(ptr, sz)
      Win32Gui.globalunlock(h)
      Win32Gui.closeclipboard
      buf.chomp(0.chr)
    end
  end

  def set_font(todo)
    hdc = Win32Gui.getdc(@hwnd)
    # selectobject(hdc, hfont)
    sz = Win32Gui.alloc_c_struct('POINT')
    Win32Gui.gettextextentpoint32a(hdc, 'x', 1, sz)
    @font_width = sz[:x]
    @font_height = sz[:y]
    Win32Gui.releasedc(@hwnd, hdc)
  end
end

class DrawableWidget < WinWidget
  include TextWidget

  BasicColor = {	:white => 'fff', :palegrey => 'ddd', :black => '000', :grey => '444',
      :red => 'f44', :darkred => '800', :palered => 'faa',
      :green => '4f4', :darkgreen => '080', :palegreen => 'afa',
      :blue => '44f', :darkblue => '008', :paleblue => 'aaf',
      :yellow => 'ff4', :darkyellow => '440', :paleyellow => 'ffa',
      :orange => 'fc8',
  }
  attr_accessor :buttons, :parent_widget
  attr_accessor :default_color_association

  def initialize(*a, &b)
    @color = {}
    @default_color_association = { :background => :winbg }
    @buttons = nil

    super()

    initialize_text
    initialize_widget(*a, &b)
  end

  def initialize_widget
  end

  def initialize_visible_
    BasicColor.each { |tag, val|
      @color[tag] = color(val)
    }
    @color[:winbg] = Win32Gui.getsyscolor(Win32Gui::COLOR_BTNFACE)
    set_color_association(@default_color_association)	# should be called after Gui.main
    set_font('courier 10')
    initialize_visible if respond_to? :initialize_visible
  end

  def set_color_association(hash)
    hord = Hash.new { |h, k| h[k] = (hash[k] ? h[hash[k]] + 1 : 0) }
    hash.sort_by { |k, v| hord[k] }.each { |k, v| @color[k] = color(v) }
    gui_update
  end

  def new_menu
    toplevel.new_menu
  end

  def addsubmenu(*a, &b)
    toplevel.addsubmenu(*a, &b)
  end

  def popupmenu(m, x, y)
    toplevel.popupmenu(m, (x+@x).to_i, (y+@y).to_i)
  end

  def paint_(realhdc)
    @hdc = Win32Gui.createcompatibledc(realhdc)
    bmp = Win32Gui.createcompatiblebitmap(realhdc, @width, @height)
    Win32Gui.selectobject(@hdc, bmp)
    Win32Gui.selectobject(@hdc, Win32Gui.getstockobject(Win32Gui::DC_BRUSH))
    Win32Gui.selectobject(@hdc, Win32Gui.getstockobject(Win32Gui::DC_PEN))
    Win32Gui.selectobject(@hdc, Win32Gui.getstockobject(Win32Gui::ANSI_FIXED_FONT))
    Win32Gui.setbkmode(@hdc, Win32Gui::TRANSPARENT)
    draw_rectangle_color(:background, 0, 0, @width, @height)
    paint
    Win32Gui.bitblt(realhdc, @x, @y, @width, @height, @hdc, 0, 0, Win32Gui::SRCCOPY)
    Win32Gui.deleteobject(bmp)
    Win32Gui.deletedc(@hdc)
    @hdc = nil
  end

  def resized_(w, h)
    @width = w
    @height = h
    resized(w, h) if respond_to? :resized
  end

  def keypress_(key)
    # XXX my gtk api sux
    if not respond_to? :keypress or not protect { keypress(key) }
      protect { @parent.keypress(key) } if @parent.respond_to? :keypress
    end
  end

  def keypress_ctrl_(key)
    if not respond_to? :keypress_ctrl or not protect { keypress_ctrl(key) }
      protect { @parent.keypress_ctrl(key) } if @parent.respond_to? :keypress_ctrl
    end
  end

  def gui_update
    redraw
  end

  def color(col)
    @color[col] ||= col.sub(/^(\w\w)(\w\w)(\w\w)$/, '\\3\\2\\1').sub(/^(\w)(\w)(\w)$/, '\\3\\3\\2\\2\\1\\1').to_i(16)
  end

  def draw_color(col)
    col = color(col)
    Win32Gui.settextcolor(@hdc, col)
    Win32Gui.setdcpencolor(@hdc, col)
    Win32Gui.setdcbrushcolor(@hdc, col)
  end

  def draw_line(x, y, ex, ey)
    Win32Gui.movetoex(@hdc, x, y, 0)
    Win32Gui.lineto(@hdc, ex, ey)
  end

  def draw_line_color(col, x, y, ex, ey)
    Win32Gui.setdcpencolor(@hdc, color(col))
    draw_line(x, y, ex, ey)
  end

  def draw_rectangle(x, y, w, h)
    Win32Gui.rectangle(@hdc, x, y, x+w, y+h)
  end

  def draw_rectangle_color(col, x, y, w, h)
    Win32Gui.setdcbrushcolor(@hdc, color(col))
    Win32Gui.setdcpencolor(@hdc, color(col))	# rect border
    draw_rectangle(x, y, w, h)
  end

  def draw_string(x, y, text)
    return if not text or text == ''
    Win32Gui.textouta(@hdc, x, y, text, text.length)
  end

  def draw_string_color(col, x, y, text)
    Win32Gui.settextcolor(@hdc, color(col))
    draw_string(x, y, text)
  end

  # same as draw_string_color + hilight @hl_word_re
  def draw_string_hl(col, x, y, str)
    if @hl_word
      while str =~ @hl_word_re
        s1, s2 = $1, $2
        draw_string_color(col, x, y, s1)
        x += s1.length*@font_width
        hl_w = s2.length*@font_width
        draw_rectangle_color(:hl_word_bg, x, y, hl_w, @font_height)
        draw_string_color(:hl_word, x, y, s2)
        x += hl_w
        str = str[s1.length+s2.length..-1]
      end
    end
    draw_string_color(col, x, y, str)
  end

  def keyboard_state(query=nil)
    case query
    when :control, :ctrl
      Win32Gui.getkeystate(Win32Gui::VK_CONTROL) & 0x8000 > 0
    when :shift
      Win32Gui.getkeystate(Win32Gui::VK_SHIFT) & 0x8000 > 0
    when :alt
      Win32Gui.getkeystate(Win32Gui::VK_MENU) & 0x8000 > 0
    else
      [:control, :shift, :alt].find_all { |s| keyboard_state(s) }
    end
  end

# represents a clickable area with a label (aka button)
class Button
  attr_accessor :x, :y, :w, :h, :c1, :c2, :text, :down, :action

  # create a new Button with the specified text & border color
  def initialize(text='Ok', c1=:palegrey, c2=:grey, &b)
    @x = @y = @w = @h = 0
    @c1, @c2 = c1, c2
    @text = text
    @down = false
    @action = b
  end

  # move the button (x y w h)
  def move(nx=@x, ny=@y, nw=@w, nh=@h)
    @x, @y, @w, @h = nx, ny, nw, nh
  end

  # draw the button on the parent widget
  def paint(w)
    c1, c2 = @c1, @c2
    c1, c2 = c2, c1 if @down
    w.draw_string_color(:text, @x+(@w-w.font_width*@text.length)/2, @y+(@h - w.font_height)/2, @text)
    w.draw_line_color(c1, @x, @y, @x, @y+@h)
    w.draw_line_color(c1, @x, @y, @x+@w, @y)
    w.draw_line_color(c2, @x+@w, @y+@h, @x, @y+@h)
    w.draw_line_color(c2, @x+@w, @y+@h, @x+@w, @y)
  end

  # checks if the click is on the button, returns true if so
  def click(x, y)
    @down = true if x >= @x and x < @x+@w and y >= @y and y < @y+@h
  end

  def mouserelease(x, y)
    if @down
      @down = false
      @action.call
      true
    end
  end
end

  # add a new button to the widget
  def add_button(text='Ok', *a, &b)
    @buttons ||= []
    @buttons << Button.new(text, *a, &b)
  end

  # render the buttons on the widget
  # should be called during #paint
  def paint_buttons
    @buttons.each { |b| b.paint(self) }
  end

  # checks if the click is inside a button, returns true if it is
  # should be called during #click
  def click_buttons(x, y)
    @buttons.find { |b| b.click(x, y) }
  end

  # the mouse was released, call button action if it is pressed
  # should be called during #mouserelease
  def mouserelease_buttons(x, y)
    @buttons.find { |b| b.mouserelease(x, y) }
  end
end

class Window
  include Msgbox

  attr_accessor :menu, :hwnd, :popups
  def initialize(*a, &b)
    @widget = nil
    @controlid = 1	# next free control id for menu items, buttons etc
    @control_action = {}
    (@@mainwindow_list ||= []) << self
    @visible = false
    @popups = []
    @parent ||= nil

    cname = "metasm_w32gui_#{object_id}"
    cls = Win32Gui.alloc_c_struct 'WNDCLASSEXA', :cbsize => :size,
        :style => Win32Gui::CS_DBLCLKS,
        :hcursor => Win32Gui.loadcursora(0, Win32Gui::IDC_ARROW),
        :lpszclassname => cname,
        :lpfnwndproc => Win32Gui.callback_alloc_c('__stdcall int wndproc(int, int, int, int)') { |hwnd, msg, wp, lp| windowproc(hwnd, msg, wp, lp) }

    Win32Gui.registerclassexa(cls)

    @hwnd = Win32Gui.createwindowexa(win32styleex, cname, 'win32gui window', win32style, Win32Gui::CW_USEDEFAULT, Win32Gui::SW_HIDE, Win32Gui::CW_USEDEFAULT, 0, 0, 0, 0, 0)

    initialize_window(*a, &b)

    if respond_to? :build_menu
      @menu = []
      @menuhwnd = 0
      build_menu
      update_menu
    end

    Win32Gui.dragacceptfiles(@hwnd, Win32Gui::TRUE)

    show
  end
  def win32styleex; 0 ; end
  def win32style; Win32Gui::WS_OVERLAPPEDWINDOW ; end

  def show
    Win32Gui.showwindow(@hwnd, Win32Gui::SW_SHOWDEFAULT)
    Win32Gui.updatewindow(@hwnd)
  end

  def keyboard_state(query=nil)
    case query
    when :control, :ctrl
      Win32Gui.getkeystate(Win32Gui::VK_CONTROL) & 0x8000 > 0
    when :shift
      Win32Gui.getkeystate(Win32Gui::VK_SHIFT) & 0x8000 > 0
    when :alt
      Win32Gui.getkeystate(Win32Gui::VK_MENU) & 0x8000 > 0
    end
  end

  # keypress event keyval traduction table
  Keyboard_trad = Win32Gui.cp.lexer.definition.keys.grep(/^VK_/).inject({}) { |h, cst|
    v = Win32Gui.const_get(cst)
    key = cst.to_s.sub(/^VK_/, '').downcase.to_sym
    h.update v => {
      :prior => :pgup, :next => :pgdown,
      :escape => :esc, :return => :enter,
      :back => :backspace, :apps => :popupmenu,
      :add => ?+, :subtract => ?-, :multiply => ?*, :divide => ?/,
    }.fetch(key, key)
  }

#MSGNAME = Win32Gui.cp.lexer.definition.keys.grep(/WM_/).sort.inject({}) { |h, c| h.update Win32Gui.const_get(c) => c }
  def windowproc(hwnd, msg, wparam, lparam)
#puts "wproc #{'%x' % hwnd} #{MSGNAME[msg] || msg} #{'%x' % wparam} #{'%x' % lparam}" if not %w[WM_NCHITTEST WM_SETCURSOR WM_MOUSEMOVE WM_NCMOUSEMOVE].include? MSGNAME[msg]
    @hwnd ||= hwnd		# some messages are sent before createwin returns
    case msg
    when Win32Gui::WM_NCHITTEST, Win32Gui::WM_SETCURSOR
      # most frequent messages (with MOUSEMOVE)
      return Win32Gui.defwindowproca(hwnd, msg, wparam, lparam)
    when Win32Gui::WM_MOUSEMOVE, Win32Gui::WM_LBUTTONDOWN, Win32Gui::WM_RBUTTONDOWN,
      Win32Gui::WM_LBUTTONDBLCLK, Win32Gui::WM_MOUSEWHEEL, Win32Gui::WM_LBUTTONUP
      mouse_msg(msg, wparam, lparam)
    when Win32Gui::WM_PAINT
      ps = Win32Gui.alloc_c_struct('PAINTSTRUCT')
      hdc = Win32Gui.beginpaint(hwnd, ps)
      if @widget
        @widget.paint_(hdc)
      else
        Win32Gui.selectobject(hdc, Win32Gui.getstockobject(Win32Gui::DC_BRUSH))
        Win32Gui.selectobject(hdc, Win32Gui.getstockobject(Win32Gui::DC_PEN))
        col = Win32Gui.getsyscolor(Win32Gui::COLOR_BTNFACE)
        Win32Gui.setdcbrushcolor(hdc, col)
        Win32Gui.setdcpencolor(hdc, col)
        Win32Gui.rectangle(hdc, 0, 0, @width, @height)
      end
      Win32Gui.endpaint(hwnd, ps)
    when Win32Gui::WM_MOVE
      rect = Win32Gui.alloc_c_struct('RECT')
      Win32Gui.getwindowrect(@hwnd, rect)
      @x, @y, @width, @height = rect[:left], rect[:top], rect[:right]-rect[:left], rect[:bottom]-rect[:top]
      @clientx = lparam & 0xffff
      @clienty = (lparam >> 16) & 0xffff
    when Win32Gui::WM_SIZE
      rect = Win32Gui.alloc_c_struct('RECT')
      Win32Gui.getwindowrect(@hwnd, rect)
      @x, @y, @width, @height = rect[:left], rect[:top], rect[:right]-rect[:left], rect[:bottom]-rect[:top]
      @clientwidth = lparam & 0xffff
      @clientheight = (lparam >> 16) & 0xffff
      @widget.resized_(lparam & 0xffff, (lparam >> 16) & 0xffff) if @widget
      redraw
    when Win32Gui::WM_WINDOWPOSCHANGING
      if @popups.first
        # must move popups to top before updating hwndInsertafter
        f = Win32Gui::SWP_NOACTIVATE | Win32Gui::SWP_NOMOVE | Win32Gui::SWP_NOSIZE |
          Win32Gui::SWP_NOOWNERZORDER | Win32Gui::SWP_NOSENDCHANGING
        @popups.each { |pw| Win32Gui.setwindowpos(pw.hwnd, Win32Gui::HWND_TOP, 0, 0, 0, 0, f) }
        Win32Gui.memory_write_int(lparam+Win32Gui.cp.typesize[:ptr], @popups.first.hwnd)
      end
    when Win32Gui::WM_SHOWWINDOW
      initialize_visible_
    when Win32Gui::WM_KEYDOWN, Win32Gui::WM_SYSKEYDOWN
      # SYSKEYDOWN for f10 (default = activate the menu bar)
      if key = Keyboard_trad[wparam]
        if [?+, ?-, ?/, ?*].include?(key)
          # keypad keys generate wm_keydown + wm_char, ignore this one
        elsif keyboard_state(:control)
          @widget.keypress_ctrl_(key) if @widget
        else
          @widget.keypress_(key) if @widget
        end
      end
      Win32Gui.defwindowproca(hwnd, msg, wparam, lparam) if key != :f10	# alt+f4 etc
    when Win32Gui::WM_CHAR
      if keyboard_state(:control) and not keyboard_state(:alt)	# altgr+[ returns CTRL on..
        if ?a.kind_of?(String)
          wparam += (keyboard_state(:shift) ? ?A.ord : ?a.ord) - 1 if wparam < 0x1a
          key = wparam.chr
        else
          wparam += (keyboard_state(:shift) ? ?A : ?a) - 1 if wparam < 0x1a
          key = wparam
        end
        @widget.keypress_ctrl_(key) if @widget
      else
        key = (?a.kind_of?(String) ? wparam.chr : wparam)
        @widget.keypress_(key) if @widget
      end
    when Win32Gui::WM_DESTROY
      destroy_window
    when Win32Gui::WM_COMMAND
      if a = @control_action[wparam]
        protect { a.call }
      end
    when Win32Gui::WM_DROPFILES
      cnt = Win32Gui.dragqueryfilea(wparam, -1, 0, 0)
      cnt.times { |i|
        buf = [0].pack('C')*1024
        len = Win32Gui.dragqueryfilea(wparam, i, buf, buf.length)
        protect { @widget.dragdropfile(buf[0, len]) } if @widget and @widget.respond_to? :dragdropfile
      }
      Win32Gui.dragfinish(wparam)
    else return Win32Gui.defwindowproca(hwnd, msg, wparam, lparam)
    end
    0
  end

  def mouse_msg(msg, wparam, lparam)
    return if not @widget
    x = Expression.make_signed(lparam & 0xffff, 16)
    y = Expression.make_signed((lparam >> 16) & 0xffff, 16)
    ctrl = true if wparam & Win32Gui::MK_CONTROL > 0
    cmsg =
    case msg
    when Win32Gui::WM_MOUSEMOVE
      :mousemove
    when Win32Gui::WM_LBUTTONDOWN
      ctrl ? :click_ctrl : :click
    when Win32Gui::WM_LBUTTONUP
      :mouserelease
    when Win32Gui::WM_RBUTTONDOWN
      :rightclick
    when Win32Gui::WM_LBUTTONDBLCLK
      :doubleclick
    when Win32Gui::WM_MOUSEWHEEL
      off = Expression.make_signed((wparam >> 16) & 0xffff, 16)
      dir = off > 0 ? :up : :down
      if ctrl
        return(@widget.mouse_wheel_ctrl(dir, x-@clientx, y-@clienty) if @widget.respond_to? :mouse_wheel_ctrl)
      else
        return(@widget.mouse_wheel(dir, x-@clientx, y-@clienty) if @widget.respond_to? :mouse_wheel)
      end
    end

    case cmsg
    when :click
      Win32Gui.setcapture(@hwnd)
    when :mouserelease
      Win32Gui.releasecapture
    end

    @widget.send(cmsg, x, y) if cmsg and @widget.respond_to? cmsg
  end

  def initialize_visible_
    return if @visible
    @visible = true
    @widget.initialize_visible_ if @widget
  end

  attr_reader :x, :y, :width, :height
  attr_reader :clientx, :clienty, :clientwidth, :clientheight
  def x=(newx)
    Win32Gui.movewindow(@hwnd, newx, @y, @width, @height, Win32Gui::TRUE)
  end
  def y=(newy)
    Win32Gui.movewindow(@hwnd, @x, newy, @width, @height, Win32Gui::TRUE)
  end
  def width=(newwidth)
    Win32Gui.movewindow(@hwnd, @x, @y, newwidth, @height, Win32Gui::TRUE)
  end
  def height=(newheight)
    Win32Gui.movewindow(@hwnd, @x, @y, @width, newheight, Win32Gui::TRUE)
  end

  def widget ; @widget ; end
  def widget=(w)
    @widget = w
    w.hwnd = @hwnd if w
    w.parent = self if w
    if @visible and w
      @widget.initialize_visible_
      rect = Win32Gui.alloc_c_struct('RECT')
      Win32Gui.getclientrect(@hwnd, rect)
      @widget.resized_(rect[:right], rect[:bottom])
    end
    redraw
  end

  def redraw
    Win32Gui.invalidaterect(@hwnd, 0, Win32Gui::FALSE)
  end

  def destroy
    Win32Gui.sendmessagea(@hwnd, Win32Gui::WM_CLOSE, 0, 0)
  end

  def destroy_window
    @destroyed = true
    @@mainwindow_list.delete self
    Gui.main_quit if @@mainwindow_list.empty?	# XXX we didn't call Gui.main, we shouldn't Gui.main_quit...
  end

  def destroyed? ; @destroyed ||= false ; end

  def new_menu
    []
  end

  # finds a menu by name (recursive)
  # returns a valid arg for addsubmenu(ret)
  def find_menu(name, from=@menu)
    name = name.gsub('_', '')
    if not l = from.find { |e| e.grep(::String).find { |es| es.gsub('_', '') == name } }
           l = from.map { |e| e.grep(::Array).map { |ae| find_menu(name, ae) }.compact.first }.compact.first
    end
    l.grep(::Array).first if l
  end

  # append stuff to a menu
  # arglist:
  # empty = menu separator
  # string = menu entry display name (use a single '_' keyboard for shortcut, eg 'Sho_rtcut' => 'r')
  # :check = menu entry is a checkbox type, add a true/false argument to specify initial value
  # second string = keyboard shortcut (accelerator) - use '^' for Ctrl, and '<up>' for special keys
  # a menu object = this entry will open a submenu (you must specify a name, and action is ignored)
  # the method takes a block or a Proc argument that will be run whenever the menu item is selected
  #
  # use @menu to reference the top-level menu bar
  # call update_menu when the menu is done
  def addsubmenu(menu, *args, &action)
    args << action if action
    menu << args
    menu.last
  end

  # make the window's MenuBar reflect the content of @menu
  def update_menu
    unuse_menu(@menu)
    Win32Gui.destroymenu(@menuhwnd) if @menuhwnd != 0
    @menuhwnd = Win32Gui.createmenu()
    @menu.each { |e| create_menu_item(@menuhwnd, e) }
    Win32Gui.setmenu(@hwnd, @menuhwnd)
  end

  def popupmenu(m, x, y)
    hm = Win32Gui.createpopupmenu()
    m.each { |e| create_menu_item(hm, e) }
    pt = Win32Gui.alloc_c_struct('POINT', :x => x, :y => y)
    Win32Gui.clienttoscreen(@hwnd, pt)
    id = Win32Gui.trackpopupmenu(hm, Win32Gui::TPM_NONOTIFY | Win32Gui::TPM_RETURNCMD, pt.x, pt.y, 0, @hwnd, 0)
    if p = @control_action[id]
      # TrackPopup returns before WM_COMMAND is delivered, so if we
      # want to cleanup @control_action we must call it now & clenup
      p.call
    end
    unuse_menu(m)
    Win32Gui.destroymenu(hm)
  end

  def unuse_menu(m)
    m.flatten.grep(Proc).reverse_each { |c|
      if @control_action[@controlid-1] == c
        @controlid -= 1		# recycle IDs
        @control_action.delete @controlid
      elsif i = @control_action.index(c)
        @control_action.delete i
      end
    }
  end

  def create_menu_item(menu, entry)
    args = entry.dup

    stock = (%w[OPEN SAVE CLOSE QUIT] & args).first
    args.delete stock if stock
    accel = args.grep(/^\^?(\w|<\w+>)$/).first
    args.delete accel if accel
    check = args.delete :check
    action = args.grep(::Proc).first
    args.delete action if action
    if submenu = args.grep(::Array).first
      args.delete submenu
      sm = Win32Gui.createmenu()
      submenu.each { |e| create_menu_item(sm, e) }
      submenu = sm
    end
    label = args.shift

    label ||= '_' + stock.capitalize if stock

    flags = 0

    if check
      checked = args.shift
      flags |= (checked ? Win32Gui::MF_CHECKED : Win32Gui::MF_UNCHECKED)
    end
    flags |= Win32Gui::MF_POPUP if submenu
    if label
      flags |= Win32Gui::MF_STRING
      label = label.gsub('&', '&&')
      label = label.tr('_', '&')
    else
      flags |= Win32Gui::MF_SEPARATOR
    end

    if accel
      key = accel[-1]
      key = accel[/<(.*)>/, 1] if key == ?>
      label += "\t#{'c-' if accel[0] == ?^}#{key.kind_of?(Integer) ? key.chr : key}"
    end

    if action
      id = @controlid
      if not check
        @control_action[id] = action
      else
        @control_action[id] = lambda {
          checked = action.call(!checked)
          Win32Gui.checkmenuitem(menu, id, (checked ? Win32Gui::MF_CHECKED : Win32Gui::MF_UNCHECKED))
        }
        entry << @control_action[id]	# allow deletion in unuse_menu
      end
      @controlid += 1
    end

    Win32Gui.appendmenua(menu, flags, id || submenu, label)
  end

  def title; @title; end
  def title=(t)
    @title = t
    Win32Gui.setwindowtexta(@hwnd, @title)
  end

  def initialize_window
  end
end

class ToolWindow < Window
  def win32styleex; Win32Gui::WS_EX_TOOLWINDOW ; end
  def win32style; Win32Gui::WS_POPUP | Win32Gui::WS_SYSMENU | Win32Gui::WS_CAPTION | Win32Gui::WS_THICKFRAME ; end

  def initialize_visible_
    super
    # center on the parent from size in initial_size
    w, h = @widget.initial_size
    r1 = Win32Gui.alloc_c_struct('RECT')
    Win32Gui.getwindowrect(@parent.hwnd, r1)
    r2 = Win32Gui.alloc_c_struct('RECT', :left => 0, :top => 0, :right => w, :bottom => h)
    Win32Gui.adjustwindowrectex(r2, @parent.win32style, Win32Gui::FALSE, @parent.win32styleex)
    x = r1[:left]+(r1[:right]-r1[:left]-r2[:right]+r2[:left])/2
    y = r1[:top ]+(r1[:bottom]-r1[:top]-r2[:bottom]+r2[:top])/2
    Win32Gui.movewindow(@hwnd, x, y, r2[:right]-r2[:left], r2[:bottom]-r2[:top], Win32Gui::FALSE)
  end

  def initialize(parent, *a, &b)
    @parent = parent
    super(*a, &b)
    @@mainwindow_list.delete self
    @parent.popups << self if parent
  end

  def destroy_window
    @parent.popups.delete self if @parent
    super
  end
end

class OpenFile
  def w32api(arg)
    Win32Gui.getopenfilenamea(arg)
  end
  def w32flags
    Win32Gui::OFN_PATHMUSTEXIST
  end

  def initialize(win, title, opts={})
    buf = [0].pack('C')*512
    ofn = Win32Gui.alloc_c_struct 'OPENFILENAMEA',
      :lstructsize => :size,
      #:hwndowner => win.hwnd,	# 0 for nonmodal
      :lpstrfilter => "All Files\0*.*\0\0",
      :lpstrfile => buf,
      :lpstrtitle => title,
      :nmaxfile => buf.length,
      :flags => Win32Gui::OFN_DONTADDTORECENT | Win32Gui::OFN_LONGNAMES |
        Win32Gui::OFN_HIDEREADONLY | w32flags
    ofn[:lpstrinitialdir] = opts[:path] if opts[:path]
    return if w32api(ofn) == 0
    buf = buf[0, buf.index(0.chr)] if buf.index(0.chr)
    yield buf if buf != ''
  end
end

class SaveFile < OpenFile
  def w32api(arg)
    Win32Gui.getsavefilenamea(arg)
  end
  def w32flags
    Win32Gui::OFN_OVERWRITEPROMPT
  end
end

class MessageBox
  def initialize(win, msg, opts={})
    opts = { :title => opts } if opts.kind_of? String
    Win32Gui.messageboxa(0, msg, opts[:title], 0)
  end
end

class InputBox < ToolWindow
class IBoxWidget < DrawableWidget
  def initialize_widget(label, opts, &b)
    @label = label
    @action = b
    @textdown = false
    @curline = opts[:text].to_s.dup
    @oldsel_x = @caret_x_select = 0
    @caret_x = @curline.length
    @caret_x_start = 0
    @@history ||= {}
    histkey = opts[:history] || label[0, 10]
    @history = (@@history[histkey] ||= [])
    @history_off = @history.length

    add_button('Ok', :btnc1, :btnc2) { keypress(:enter) }
    add_button('Cancel', :btnc1, :btnc2) { keypress(:esc) }

    @default_color_association = { :background => :winbg, :label => :black,
      :text => :black, :textbg => :white, :caret => :black, :btnc1 => :palegrey,
      :btnc2 => :grey, :textsel => :white, :textselbg => :darkblue }
  end

  def resized(w, h)
    bw = 10*@font_width
    bh = @font_height*3/2
    @buttons[0].move((w-2*bw-3*@font_width)/2, 0, bw, bh)
    @buttons[1].move(@buttons[0].x + 3*@font_width + bw, 0, bw, bh)
  end

  def initial_size
    [40*@font_width, 6*@font_height + @font_height/4]
  end

  def paint
    y = @font_height/2

    fixedfont = Win32Gui.selectobject(@hdc, Win32Gui.getstockobject(Win32Gui::ANSI_VAR_FONT))
    sz = Win32Gui.alloc_c_struct('POINT')
    Win32Gui.gettextextentpoint32a(@hdc, 'x', 1, sz)
    var_font_height = sz[:y]
    @label.each_line { |l|
      draw_string_color(:label, @font_width, y, l)
      y += var_font_height
    }
    y += @font_height
    @texty = y-1
    @texth = @font_height+1

    Win32Gui.selectobject(@hdc, fixedfont)

    y += @font_height*2
    @buttons.each { |b| b.y = y }
    paint_buttons

    w_c = width/@font_width - 2

    if @caret_x <= @caret_x_start
      @caret_x_start = [@caret_x-1, 0].max
    elsif @caret_x_start > 0 and @curline[@caret_x_start..-1].length < w_c-1
      @caret_x_start = [@curline.length-w_c+1, 0].max
    elsif @caret_x_start + w_c <= @caret_x
      @caret_x_start = [@caret_x-w_c+1, 0].max
    end
    draw_rectangle_color(:textbg, @font_width, @texty-1, @width-2*@font_width, @font_height+1)
    draw_string_color(:text, @font_width+1, @texty, @curline[@caret_x_start, w_c])

    if @caret_x_select
      c1, c2 = [@caret_x_select, @caret_x].sort
      c1 = [[c1, @caret_x_start].max, @caret_x_start+w_c].min
      c2 = [[c2, @caret_x_start].max, @caret_x_start+w_c].min
      if c1 != c2
        draw_rectangle_color(:textselbg, @font_width+1+(c1-@caret_x_start)*@font_width, @texty-1, (c2-c1)*@font_width, @font_height+1)
        draw_string_color(:textsel, @font_width+1+(c1-@caret_x_start)*@font_width, @texty, @curline[c1...c2])
      end
    end

    cx = [@caret_x-@caret_x_start+1, w_c].min*@font_width+1
    draw_line_color(:caret, cx, @texty, cx, @texty+@font_height-1)
    @oldcaret_x = @caret_x
  end

  def keypress_ctrl(key)
    case key
    when ?a
      @caret_x_select = 0
      @caret_x = @curline.length
      redraw
    when ?c
      if @caret_x_select
        c1, c2 = [@caret_x, @caret_x_select].sort
        clipboard_copy @curline[c1...c2]
      end
    when ?v
      cptext = clipboard_paste.to_s
      cx = @caret_x_select || @caret_x
      @caret_x_select = nil
      c1, c2 = [cx, @caret_x].sort
      @curline[c1...c2] = cptext
      @caret_x_select = nil
      @caret_x = c1 + cptext.length
      redraw
    when ?x
      if @caret_x_select
        c1, c2 = [@caret_x, @caret_x_select].sort
        clipboard_copy @curline[c1...c2]
        @curline[c1..c2] = ''
        @caret_x_select = nil
        @caret_x = c1
        redraw
      end
    else return false
    end
    true
  end

  def keypress(key)
    case key
    when :left
      if keyboard_state(:shift)
        @caret_x_select ||= @caret_x
      else
        @caret_x_select = nil
      end
      @caret_x -= 1 if @caret_x > 0
      update_caret
    when :right
      if keyboard_state(:shift)
        @caret_x_select ||= @caret_x
      else
        @caret_x_select = nil
      end
      @caret_x += 1 if @caret_x < @curline.length
      update_caret
    when :home
      if keyboard_state(:shift)
        @caret_x_select ||= @caret_x
      else
        @caret_x_select = nil
      end
      @caret_x = 0
      update_caret
    when :end
      if keyboard_state(:shift)
        @caret_x_select ||= @caret_x
      else
        @caret_x_select = nil
      end
      @caret_x = @curline.length
      update_caret
    when :up, :down
      if @history_off < @history.length or @curline.strip != @history.last
        @history[@history_off] = @curline.strip
      end
      @history_off += (key == :up ? -1 : 1)
      @history_off %= @history.length
      @curline = @history[@history_off].to_s
      @caret_x = @curline.length if @caret_x > @curline.length
      redraw
    when :enter
      @history << @curline.strip
      @history.pop if @history.last == ''
      @history.pop if @history.last == @history[-2]
      destroy
      Gui.main_iter
      protect { @action.call(@curline.strip) }
    when :esc
      if @buttons.find { |b| b.down }
        @buttons.each { |b| b.down = false }
        redraw
      else
        destroy
      end
    when ?\x20..?\x7e
      cx = @caret_x_select || @caret_x
      @caret_x_select = nil
      c1, c2 = [cx, @caret_x].sort
      @curline[c1...c2] = key.chr
      @caret_x = c1+1
      redraw
    when :delete
      if @caret_x_select
        c1, c2 = [@caret_x, @caret_x_select].sort
        @curline[c1...c2] = ''
        @caret_x_select = nil
        @caret_x = c1
        redraw
      elsif @caret_x < @curline.length
        @curline[@caret_x, 1] = ''
        redraw
      end
    when :backspace
      if @caret_x_select
        c1, c2 = [@caret_x, @caret_x_select].sort
        @curline[c1...c2] = ''
        @caret_x_select = nil
        @caret_x = c1
        redraw
      elsif @caret_x > 0
        @caret_x -= 1
        @curline[@caret_x, 1] = ''
        redraw
      end
    else return false
    end
    true
  end

  def click(x, y)
    if y >= @texty and y < @texty+@texth
      @caret_x_select = nil
      @caret_x = x.to_i / @font_width - 1 + @caret_x_start
      @caret_x = [[@caret_x, 0].max, @curline.length].min
      @textdown = @caret_x
      update_caret
    elsif click_buttons(x, y)
      redraw
    end
  end

  def mousemove(x, y)
    if @textdown
      x = x.to_i / @font_width - 1 + @caret_x_start
      x = [[x, 0].max, @curline.length].min
      if x != @textdown
        @caret_x_select = @textdown
        @caret_x = x
        redraw
      end
    end
  end

  def mouserelease(x, y)
    if @textdown
      x = x.to_i / @font_width - 1 + @caret_x_start
      x = [[x, 0].max, @curline.length].min
      if x != @textdown
        @caret_x_select = @textdown
        @caret_x = x
        redraw
      end
      @textdown = false
    elsif mouserelease_buttons(x, y)
    end
  end

  def update_caret
    return if @oldcaret_x == @caret_x and @oldsel_x == @caret_x_select
    redraw
    @oldsel_x = @caret_x_select
    @oldcaret_x = @caret_x
  end

  def destroy
    @parent.destroy
  end

  def text
    @curline
  end
  def text=(t)
    @curline = t
    @caret_x_select = 0
    @caret_x = t.length
    redraw
  end

  def dragdropfile(f)
    cx = @caret_x_select || @caret_x
    @caret_x_select = nil
    c1, c2 = [cx, @caret_x].sort
    @curline[c1...c2] = f
    @caret_x_select = nil
    @caret_x = c1 + f.length
    redraw
  end
end
  def initialize_window(prompt, opts={}, &b)
    self.title = opts[:title] ? opts[:title] : 'input'
    self.widget = IBoxWidget.new(prompt, opts, &b)
  end

  def text ; @widget.text ; end
  def text=(t) ; @widget.text = t ; end
end

class ListWindow < ToolWindow
class LBoxWidget < DrawableWidget
  def initialize_widget(list, opts={}, &b)
    ccnt = list.first.length
    # store a true/false per column saying if the original data was integers (for col sorting)
    @list_ints = list[1..-1].transpose.map { |col| col.all? { |e| e.kind_of? Integer } } rescue []
    @list = list.map { |l|
      l += ['']*(ccnt - l.length) if l.length < ccnt
      l = l[0, ccnt] if l.length > ccnt
      l.map { |w| w.to_s }
    }
    # length of the longest element of the column
    @colwmax = @list.transpose.map { |l| l.map { |w| w.length }.max }
    @titles = @list.shift

    @action = b
    @linehead = 0
    @color_callback = opts[:color_callback]	# lambda { |ary_entries_text| [color_font, color_bg] }
    @noclose_dblclick = opts[:noclose_dblclick]
    # index of the currently selected row
    @linesel = nil
    # ary indicating whether a title label is being clicked
    @btndown = []
    @btnheight = @font_height * 4/3
    @sbh = 0	# position of the hz scrollbar
    @sbv = 0

    @default_color_association = { :background => :winbg, :label => :black,
      :text => :black, :textbg => :white, :btnc1 => :white, :btnc2 => :grey,
      :textsel => :white, :textselbg => :darkblue }
  end

  def initial_size
    @colw = @colwmax.map { |w| (w+1) * @font_width }
    allw = @colw.inject(0) { |a, i| a+i }
    [[allw, 80*@font_width].min, [@list.length+1, 30].min * @font_height+2]
  end

  def resized(w, h)
    # scrollbar stuff
    fullw = @colwmax.inject(0) { |a, i| a+i+1 } * @font_width
    @sbh = fullw-w if @sbh > fullw-w
    @sbh = 0 if @sbh < 0
    sif = Win32Gui.alloc_c_struct('SCROLLINFO',
      :cbsize => :size, :fmask => Win32Gui::SIF_ALL,
      :nmin => 0, :nmax => fullw-1, :npage => w, :npos => @sbh)
    Win32Gui.setscrollinfo(@hwnd, Win32Gui::SB_HORZ, sif, Win32Gui::TRUE)

    fullh = @list.length * @font_height + @btnheight
    @sbv = fullh-h if @sbv > fullh-h
    @sbv = 0 if @sbv < 0
    sif = Win32Gui.alloc_c_struct('SCROLLINFO',
      :cbsize => :size, :fmask => Win32Gui::SIF_ALL,
      :nmin => 0, :nmax => fullh-1, :npage => h, :npos => @sbv)
    Win32Gui.setscrollinfo(@hwnd, Win32Gui::SB_VERT, sif, Win32Gui::TRUE)

    # resize columns to fill available hz space
    if w > fullw
      mi = (w-fullw) / @colw.length
      mm = (w-fullw) % @colw.length
      @colw.length.times { |i|
        @colw[i] = (@colwmax[i]+1)*@font_width + mi + (i < mm ? 1 : 0)
      }
      redraw
    end
  end

  def paint
    @btnx = []
    @btny = 0
    if @btnheight != @font_height * 4/3
      # fix vscrollbar height on w7
      @btnheight = @font_height * 4/3
      resized(width, height)
    end
    x = 0
    @colw.each { |w|
      @btnx << x
      x += w
    }

    x -= @sbh
    y = @btnheight
    @linehead = @sbv / @font_height
    y -= @sbv % @font_height
    tl = (@linesel || -1) - @linehead
    @lineshown = @list[@linehead, (height-y)/@font_height+1].to_a.length
    @list[@linehead, @lineshown].to_a.each { |l|
      x = @btnx.first - @sbh
      ct, cb = @color_callback[l] if @color_callback
      ct ||= :text
      cb ||= :textbg
      ct, cb = :textsel, :textselbg if tl == 0
      tl -= 1
      draw_rectangle_color(cb, x, y, width-2*x, @font_height)
      l.zip(@colw).each { |t, w|
        draw_string_color(ct, x+@font_width/2, y, t[0, w/@font_width-1])
        x += w
      }
      y += @font_height
    }

    @titles.zip(@colw, @btnx, @btndown).each { |t, w, bx, d|
      x = bx - @sbh
      y = @btny
      h = @btnheight-1
      c1 = d ? :btnc2 : :btnc1
      c2 = d ? :btnc1 : :btnc2
      draw_rectangle_color(:background, x, y, w-1, h)
      draw_line_color(c1, x, y, x, y+h)
      draw_line_color(c1, x, y, x+w-1, y)
      draw_line_color(c2, x+w-1, y+h, x, y+h)
      draw_line_color(c2, x+w-1, y+h, x+w-1, y)

      cw = w/@font_width-1
      xo = [(cw-t.length) * @font_width/2, 0].max	# center titles
      draw_string_color(:label, x+@font_width/2+xo, y+@font_height/6, t[0, cw])
    }
  end

  def keypress(key)
    case key
    when :up
      if not @linesel
        @linesel = @linehead
      elsif @linesel > 0
        @linesel -= 1
        vscroll(@linesel*@font_height) if @linesel < @linehead
      end
      redraw
    when :down
      if not @linesel
        @linesel = @linehead
      elsif @linesel < @list.length-1
        @linesel += 1
        vscroll((@linesel-(@lineshown-1))*@font_height) if @linehead < @linesel-(@lineshown-1)
      end
      redraw
    when :pgup
      off = [@lineshown, [@lineshown/2, 5].max].min
      if not @linesel
        @linesel = @linehead
      elsif @linesel != @linehead
        @linesel = [@linehead, @linesel-off].max
      else
        @linesel = [0, @linehead-off].max
        vscroll(@linesel*@font_height)
      end
      redraw
    when :pgdown
      n = @lineshown-1
      off = [@lineshown, [@lineshown/2, 5].max].min
      if not @linesel
        @linesel = @linehead+n
      elsif @linesel != @linehead+n
        @linesel = [@linehead+n, @linesel+off].min
      else
        vscroll((@linehead+off)*@font_height)
        @linesel = [@linehead+n, @list.length-1].min
      end
      redraw
    when :home
      @linesel = 0
      vscroll(0)
      redraw
    when :end
      @linesel = @list.length-1
      vscroll(@list.length*@font_height)
      redraw
    when :enter
      if @linesel and @list[@linesel]
        protect { @action.call(@list[@linesel]) }
      end
    when :esc
      if not @btndown.compact.empty?
        @btndown = []
        redraw
      else
        destroy
      end
    else return false
    end
    true
  end

  def mouse_wheel(dir, x, y)
    case dir
    when :up
      off = [@lineshown, [@lineshown/2, 5].max].min
      vscroll((@linehead-off)*@font_height)
      redraw
    when :down
      off = [@lineshown, [@lineshown/2, 5].max].min
      vscroll((@linehead+off)*@font_height)
      redraw
    end
  end

  def hscroll(val)
    Win32Gui.setscrollpos(@hwnd, Win32Gui::SB_HORZ, val, Win32Gui::TRUE)
    @sbh = Win32Gui.getscrollpos(@hwnd, Win32Gui::SB_HORZ)	# clipping, etc
    redraw
  end

  def vscroll(val)
    Win32Gui.setscrollpos(@hwnd, Win32Gui::SB_VERT, val, Win32Gui::TRUE)
    @sbv = Win32Gui.getscrollpos(@hwnd, Win32Gui::SB_VERT)
    redraw
  end

  def xtobtn(x)
    x += @sbh
    if x < @btnx.first
      return 0
    elsif x >= @btnx.last + @colw.last
      return @btnx.length-1
    else
      @btnx.zip(@colw).each_with_index { |(bx, bw), i|
        return i if x >= bx and x < bx+bw
      }
    end
  end

  def click(x, y)
    if y >= @btny and y < @btny+@btnheight
      # TODO column resize
      @btndown[xtobtn(x)] = true
      redraw
    elsif y >= @btny+@btnheight
      y += @sbv % @font_height
      cy = @linehead + (y - @btny - @btnheight)/@font_height
      if cy < @list.length
        @linesel = cy
        redraw
        Gui.main_iter
        protect { @action.call(@list[@linesel]) }
      end
    end
  end

  def doubleclick(x, y)
    if y >= @btny+@btnheight
      return click(x, y) if @noclose_dblclick
      y += @sbv % @font_height
      cy = @linehead + (y - @btny - @btnheight)/@font_height
      if cy < @list.length
        destroy
        Gui.main_iter
        protect { @action.call(@list[@linesel]) }
      end
    end
  end

  def mousemove(x, y)
    if @btndown.compact.first
      @btndown = []
      @btndown[xtobtn(x)] = true
      redraw
    end
  end

  def mouserelease(x, y)
    if @btndown.compact.first
      @btndown = []
      col = xtobtn(x)
      cursel = @list[@linesel] if @linesel
      if @list_ints[col]
        nlist = @list.sort_by { |a| [a[col].to_i, a] }
      else
        nlist = @list.sort_by { |a| [a[col], a] }
      end
      nlist.reverse! if nlist == @list
      @list = nlist
      @linehead = 0
      if cursel
        @linesel = @list.index(cursel)
        @linehead = @linesel - (@lineshown-1) if @linehead < @linesel-(@lineshown-1)
      end
      redraw
    end
  end

  def destroy
    @parent.destroy
  end
end
  def initialize_window(title, list, opts={}, &b)
    @ondestroy = opts[:ondestroy]
    self.title = title
    self.widget = LBoxWidget.new(list, opts, &b)
  end

  def destroy_window
    @ondestroy.call if @ondestroy
    super()
  end

  def windowproc(hwnd, msg, wparam, lparam)
    case msg
    when Win32Gui::WM_HSCROLL
      sif = Win32Gui.alloc_c_struct('SCROLLINFO', :cbsize => :size, :fmask => Win32Gui::SIF_ALL)
      Win32Gui.getscrollinfo(@hwnd, Win32Gui::SB_HORZ, sif)
      case wparam & 0xffff
      when Win32Gui::SB_THUMBPOSITION; val = sif.ntrackpos
      when Win32Gui::SB_THUMBTRACK; val = sif.ntrackpos
      when Win32Gui::SB_LINELEFT;  val = sif.npos - 1
      when Win32Gui::SB_LINERIGHT; val = sif.npos + 1
      when Win32Gui::SB_PAGELEFT;  val = sif.npos - sif.npage
      when Win32Gui::SB_PAGERIGHT; val = sif.npos + sif.npage
      else return 0
      end
      @widget.hscroll val
    when Win32Gui::WM_VSCROLL
      sif = Win32Gui.alloc_c_struct('SCROLLINFO', :cbsize => :size, :fmask => Win32Gui::SIF_ALL)
      Win32Gui.getscrollinfo(@hwnd, Win32Gui::SB_VERT, sif)
      case wparam & 0xffff
      when Win32Gui::SB_THUMBPOSITION; val = sif.ntrackpos
      when Win32Gui::SB_THUMBTRACK; val = sif.ntrackpos #; nopos = true
      when Win32Gui::SB_LINEDOWN; val = sif.npos + 1
      when Win32Gui::SB_LINEUP;   val = sif.npos - 1
      when Win32Gui::SB_PAGEDOWN; val = sif.npos + sif.npage
      when Win32Gui::SB_PAGEUP;   val = sif.npos - sif.npage
      else return 0
      end
      @widget.vscroll val
    else return super(hwnd, msg, wparam, lparam)
    end
    0
  end
end

def Gui.main
  @idle_procs ||= []
  msg = Win32Gui.alloc_c_struct('MSG')
  loop do
    if Win32Gui.peekmessagea(msg, 0, 0, 0, Win32Gui::PM_NOREMOVE) != 0 or
        Win32Gui.msgwaitformultipleobjects(0, 0, Win32Gui::FALSE, 500,
          Win32Gui::QS_ALLINPUT) != Win32Gui::WAIT_TIMEOUT
      ret = Win32Gui.getmessagea(msg, 0, 0, 0)
      break if ret == 0
      raise Win32Gui.last_error_msg if ret < 0
      Win32Gui.translatemessage(msg)
      Win32Gui.dispatchmessagea(msg)
    end
    while not @idle_procs.empty? and Win32Gui.peekmessagea(msg, 0, 0, 0, Win32Gui::PM_NOREMOVE) == 0
      @idle_procs.delete_if { |ip| not ip.call }
    end
  end
  msg[:wparam]
end

def Gui.main_quit
  Win32Gui.postquitmessage(0)
end

def Gui.main_iter
  msg = Win32Gui.alloc_c_struct('MSG')
  while Win32Gui.peekmessagea(msg, 0, 0, 0, Win32Gui::PM_REMOVE) != 0
    Win32Gui.translatemessage(msg)
    Win32Gui.dispatchmessagea(msg)
  end
end

# add a lambda to be run whenever the messageloop is idle
# the lambda is removed if it returns nil/false
def Gui.idle_add(&b)
  @idle_procs ||= []
  @idle_procs << b
end

end
end

require 'metasm/gui/dasm_main'
require 'metasm/gui/debug'

