const std = @import("std");
const platform = @import("platform.zig");
const debug = @import("debug.zig");
const wss_client = @import("wss_client.zig");

const win = std.os.windows;

// ------------------------------------------------------------------
// Constants not present in Zig 0.15 std library
// ------------------------------------------------------------------
const WM_CREATE = 0x0001;
const WM_DESTROY = 0x0002;
const WM_MOVE = 0x0003;
const WM_SIZE = 0x0005;
const WM_ACTIVATE = 0x0006;
const WM_SETFOCUS = 0x0007;
const WM_KILLFOCUS = 0x0008;
const WM_PAINT = 0x000F;
const WM_CLOSE = 0x0010;
const WM_QUIT = 0x0012;
const WM_ERASEBKGND = 0x0014;
const WM_SHOWWINDOW = 0x0018;
const WM_ACTIVATEAPP = 0x001C;
const WM_SETCURSOR = 0x0020;
const WM_MOUSEACTIVATE = 0x0021;
const WM_GETMINMAXINFO = 0x0024;
const WM_WINDOWPOSCHANGING = 0x0046;
const WM_WINDOWPOSCHANGED = 0x0047;
const WM_CONTEXTMENU = 0x007B;
const WM_STYLECHANGING = 0x007C;
const WM_STYLECHANGED = 0x007D;
const WM_NCCREATE = 0x0081;
const WM_NCDESTROY = 0x0082;
const WM_NCCALCSIZE = 0x0083;
const WM_NCHITTEST = 0x0084;
const WM_NCPAINT = 0x0085;
const WM_NCACTIVATE = 0x0086;
const WM_KEYDOWN = 0x0100;
const WM_KEYUP = 0x0101;
const WM_CHAR = 0x0102;
const WM_SYSKEYDOWN = 0x0104;
const WM_SYSKEYUP = 0x0105;
const WM_SYSCHAR = 0x0106;
const WM_INITDIALOG = 0x0110;
const WM_COMMAND = 0x0111;
const WM_SYSCOMMAND = 0x0112;
const WM_TIMER = 0x0113;
const WM_HSCROLL = 0x0114;
const WM_VSCROLL = 0x0115;
const WM_INITMENU = 0x0116;
const WM_INITMENUPOPUP = 0x0117;
const WM_MENUSELECT = 0x011F;
const WM_MENUCHAR = 0x0120;
const WM_ENTERIDLE = 0x0121;
const WM_MENURBUTTONUP = 0x0122;
const WM_MENUDRAG = 0x0123;
const WM_MENUGETOBJECT = 0x0124;
const WM_UNINITMENUPOPUP = 0x0125;
const WM_MENUCOMMAND = 0x0126;
const WM_CHANGEUISTATE = 0x0127;
const WM_UPDATEUISTATE = 0x0128;
const WM_QUERYUISTATE = 0x0129;
const WM_CTLCOLORMSGBOX = 0x0132;
const WM_CTLCOLOREDIT = 0x0133;
const WM_CTLCOLORLISTBOX = 0x0134;
const WM_CTLCOLORBTN = 0x0135;
const WM_CTLCOLORDLG = 0x0136;
const WM_CTLCOLORSCROLLBAR = 0x0137;
const WM_CTLCOLORSTATIC = 0x0138;
const WM_MOUSEMOVE = 0x0200;
const WM_LBUTTONDOWN = 0x0201;
const WM_LBUTTONUP = 0x0202;
const WM_LBUTTONDBLCLK = 0x0203;
const WM_RBUTTONDOWN = 0x0204;
const WM_RBUTTONUP = 0x0205;
const WM_RBUTTONDBLCLK = 0x0206;
const WM_MBUTTONDOWN = 0x0207;
const WM_MBUTTONUP = 0x0208;
const WM_MBUTTONDBLCLK = 0x0209;
const WM_MOUSEWHEEL = 0x020A;
const WM_XBUTTONDOWN = 0x020B;
const WM_XBUTTONUP = 0x020C;
const WM_XBUTTONDBLCLK = 0x020D;
const WM_PARENTNOTIFY = 0x0210;
const WM_ENTERMENULOOP = 0x0211;
const WM_EXITMENULOOP = 0x0212;
const WM_NEXTMENU = 0x0213;
const WM_CAPTURECHANGED = 0x0215;
const WM_MOVING = 0x0216;
const WM_POWERBROADCAST = 0x0218;
const WM_DEVICECHANGE = 0x0219;
const WM_IME_SETCONTEXT = 0x0281;
const WM_IME_NOTIFY = 0x0282;
const WM_IME_CONTROL = 0x0283;
const WM_IME_COMPOSITIONFULL = 0x0284;
const WM_IME_SELECT = 0x0285;
const WM_IME_CHAR = 0x0286;
const WM_IME_REQUEST = 0x0288;
const WM_IME_KEYDOWN = 0x0290;
const WM_IME_KEYUP = 0x0291;
const WM_NCMOUSEHOVER = 0x02A0;
const WM_MOUSEHOVER = 0x02A1;
const WM_NCMOUSELEAVE = 0x02A2;
const WM_MOUSELEAVE = 0x02A3;
const WM_WTSSESSION_CHANGE = 0x02B1;
const WM_TABLET_FIRST = 0x02C0;
const WM_TABLET_LAST = 0x02DF;
const WM_DPICHANGED = 0x02E0;
const WM_CUT = 0x0300;
const WM_COPY = 0x0301;
const WM_PASTE = 0x0302;
const WM_CLEAR = 0x0303;
const WM_UNDO = 0x0304;
const WM_RENDERFORMAT = 0x0305;
const WM_RENDERALLFORMATS = 0x0306;
const WM_DESTROYCLIPBOARD = 0x0307;
const WM_DRAWCLIPBOARD = 0x0308;
const WM_PAINTCLIPBOARD = 0x0309;
const WM_VSCROLLCLIPBOARD = 0x030A;
const WM_SIZECLIPBOARD = 0x030B;
const WM_ASKCBFORMATNAME = 0x030C;
const WM_CHANGECBCHAIN = 0x030D;
const WM_HSCROLLCLIPBOARD = 0x030E;
const WM_QUERYNEWPALETTE = 0x030F;
const WM_PALETTEISCHANGING = 0x0310;
const WM_PALETTECHANGED = 0x0311;
const WM_HOTKEY = 0x0312;
const WM_PRINT = 0x0317;
const WM_PRINTCLIENT = 0x0318;
const WM_APPCOMMAND = 0x0319;
const WM_THEMECHANGED = 0x031A;
const WM_CLIPBOARDUPDATE = 0x031D;
const WM_DWMCOMPOSITIONCHANGED = 0x031E;
const WM_DWMNCRENDERINGCHANGED = 0x031F;
const WM_DWMCOLORIZATIONCOLORCHANGED = 0x0320;
const WM_DWMWINDOWMAXIMIZEDCHANGE = 0x0321;
const WM_DWMSENDICONICTHUMBNAIL = 0x0323;
const WM_DWMSENDICONICLIVEPREVIEWBITMAP = 0x0326;
const WM_GETTITLEBARINFOEX = 0x033F;
const WM_GETTITLEBARINFO = 0x033F;
const WM_APP = 0x8000;
const WM_USER = 0x0400;

const WS_OVERLAPPED = 0x00000000;
const WS_POPUP = 0x80000000;
const WS_CHILD = 0x40000000;
const WS_MINIMIZE = 0x20000000;
const WS_VISIBLE = 0x10000000;
const WS_DISABLED = 0x08000000;
const WS_CLIPSIBLINGS = 0x04000000;
const WS_CLIPCHILDREN = 0x02000000;
const WS_MAXIMIZE = 0x01000000;
const WS_CAPTION = 0x00C00000;
const WS_BORDER = 0x00800000;
const WS_DLGFRAME = 0x00400000;
const WS_VSCROLL = 0x00200000;
const WS_HSCROLL = 0x00100000;
const WS_SYSMENU = 0x00080000;
const WS_THICKFRAME = 0x00040000;
const WS_GROUP = 0x00020000;
const WS_TABSTOP = 0x00010000;
const WS_MINIMIZEBOX = 0x00020000;
const WS_MAXIMIZEBOX = 0x00010000;
const WS_OVERLAPPEDWINDOW = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX;

const WS_EX_DLGMODALFRAME = 0x00000001;
const WS_EX_NOPARENTNOTIFY = 0x00000004;
const WS_EX_TOPMOST = 0x00000008;
const WS_EX_ACCEPTFILES = 0x00000010;
const WS_EX_TRANSPARENT = 0x00000020;
const WS_EX_MDICHILD = 0x00000040;
const WS_EX_TOOLWINDOW = 0x00000080;
const WS_EX_WINDOWEDGE = 0x00000100;
const WS_EX_CLIENTEDGE = 0x00000200;
const WS_EX_CONTEXTHELP = 0x00000400;
const WS_EX_RIGHT = 0x00001000;
const WS_EX_LEFT = 0x00000000;
const WS_EX_RTLREADING = 0x00002000;
const WS_EX_LTRREADING = 0x00000000;
const WS_EX_LEFTSCROLLBAR = 0x00004000;
const WS_EX_RIGHTSCROLLBAR = 0x00000000;
const WS_EX_CONTROLPARENT = 0x00010000;
const WS_EX_STATICEDGE = 0x00020000;
const WS_EX_APPWINDOW = 0x00040000;
const WS_EX_OVERLAPPEDWINDOW = WS_EX_WINDOWEDGE | WS_EX_CLIENTEDGE;
const WS_EX_PALETTEWINDOW = WS_EX_WINDOWEDGE | WS_EX_TOOLWINDOW | WS_EX_TOPMOST;
const WS_EX_LAYERED = 0x00080000;
const WS_EX_NOINHERITLAYOUT = 0x00100000;
const WS_EX_LAYOUTRTL = 0x00400000;
const WS_EX_COMPOSITED = 0x02000000;
const WS_EX_NOACTIVATE = 0x08000000;

const ES_LEFT = 0x0000;
const ES_CENTER = 0x0001;
const ES_RIGHT = 0x0002;
const ES_MULTILINE = 0x0004;
const ES_UPPERCASE = 0x0008;
const ES_LOWERCASE = 0x0010;
const ES_PASSWORD = 0x0020;
const ES_AUTOVSCROLL = 0x0040;
const ES_AUTOHSCROLL = 0x0080;
const ES_NOHIDESEL = 0x0100;
const ES_OEMCONVERT = 0x0400;
const ES_READONLY = 0x0800;
const ES_WANTRETURN = 0x1000;
const ES_NUMBER = 0x2000;

const BS_PUSHBUTTON = 0x00000000;
const BS_DEFPUSHBUTTON = 0x00000001;
const BS_CHECKBOX = 0x00000002;
const BS_AUTOCHECKBOX = 0x00000003;
const BS_RADIOBUTTON = 0x00000004;
const BS_3STATE = 0x00000005;
const BS_AUTO3STATE = 0x00000006;
const BS_GROUPBOX = 0x00000007;
const BS_USERBUTTON = 0x00000008;
const BS_AUTORADIOBUTTON = 0x00000009;
const BS_PUSHBOX = 0x0000000A;
const BS_OWNERDRAW = 0x0000000B;
const BS_TYPEMASK = 0x0000000F;
const BS_LEFTTEXT = 0x00000020;
const BS_TEXT = 0x00000000;
const BS_ICON = 0x00000040;
const BS_BITMAP = 0x00000080;
const BS_LEFT = 0x00000100;
const BS_RIGHT = 0x00000200;
const BS_CENTER = 0x00000300;
const BS_TOP = 0x00000400;
const BS_BOTTOM = 0x00000800;
const BS_VCENTER = 0x00000C00;
const BS_PUSHLIKE = 0x00001000;
const BS_MULTILINE = 0x00002000;
const BS_NOTIFY = 0x00004000;
const BS_FLAT = 0x00008000;
const BS_RIGHTBUTTON = BS_LEFTTEXT;

const CS_VREDRAW = 0x0001;
const CS_HREDRAW = 0x0002;
const CS_DBLCLKS = 0x0008;
const CS_OWNDC = 0x0020;
const CS_CLASSDC = 0x0040;
const CS_PARENTDC = 0x0080;
const CS_NOCLOSE = 0x0200;
const CS_SAVEBITS = 0x0800;
const CS_BYTEALIGNCLIENT = 0x1000;
const CS_BYTEALIGNWINDOW = 0x2000;
const CS_GLOBALCLASS = 0x4000;
const CS_IME = 0x00010000;
const CS_DROPSHADOW = 0x00020000;

const SW_HIDE = 0;
const SW_SHOWNORMAL = 1;
const SW_SHOWMINIMIZED = 2;
const SW_SHOWMAXIMIZED = 3;
const SW_SHOWNOACTIVATE = 4;
const SW_SHOW = 5;
const SW_MINIMIZE = 6;
const SW_SHOWMINNOACTIVE = 7;
const SW_SHOWNA = 8;
const SW_RESTORE = 9;
const SW_SHOWDEFAULT = 10;
const SW_FORCEMINIMIZE = 11;

const MF_INSERT = 0x00000000;
const MF_CHANGE = 0x00000080;
const MF_APPEND = 0x00000100;
const MF_DELETE = 0x00000200;
const MF_REMOVE = 0x00001000;
const MF_BYCOMMAND = 0x00000000;
const MF_BYPOSITION = 0x00000400;
const MF_SEPARATOR = 0x00000800;
const MF_ENABLED = 0x00000000;
const MF_GRAYED = 0x00000001;
const MF_DISABLED = 0x00000002;
const MF_UNCHECKED = 0x00000000;
const MF_CHECKED = 0x00000008;
const MF_USECHECKBITMAPS = 0x00000200;
const MF_STRING = 0x00000000;
const MF_BITMAP = 0x00000004;
const MF_OWNERDRAW = 0x00000100;
const MF_POPUP = 0x00000010;
const MF_MENUBARBREAK = 0x00000020;
const MF_MENUBREAK = 0x00000040;
const MF_UNHILITE = 0x00000000;
const MF_HILITE = 0x00000080;
const MF_DEFAULT = 0x00001000;
const MF_SYSMENU = 0x00002000;
const MF_HELP = 0x00004000;
const MF_RIGHTJUSTIFY = 0x00004000;
const MF_MOUSESELECT = 0x00008000;

const MB_OK = 0x00000000;
const MB_OKCANCEL = 0x00000001;
const MB_ABORTRETRYIGNORE = 0x00000002;
const MB_YESNOCANCEL = 0x00000003;
const MB_YESNO = 0x00000004;
const MB_RETRYCANCEL = 0x00000005;
const MB_CANCELTRYCONTINUE = 0x00000006;
const MB_ICONHAND = 0x00000010;
const MB_ICONQUESTION = 0x00000020;
const MB_ICONEXCLAMATION = 0x00000030;
const MB_ICONASTERISK = 0x00000040;
const MB_USERICON = 0x00000080;
const MB_ICONWARNING = MB_ICONEXCLAMATION;
const MB_ICONERROR = MB_ICONHAND;
const MB_ICONINFORMATION = MB_ICONASTERISK;
const MB_ICONSTOP = MB_ICONHAND;

const IDC_ARROW = @as([*:0]const u16, @ptrFromInt(32512));
const IDC_IBEAM = @as([*:0]const u16, @ptrFromInt(32513));
const IDC_WAIT = @as([*:0]const u16, @ptrFromInt(32514));
const IDC_CROSS = @as([*:0]const u16, @ptrFromInt(32515));
const IDC_UPARROW = @as([*:0]const u16, @ptrFromInt(32516));
const IDC_SIZE = @as([*:0]const u16, @ptrFromInt(32640));
const IDC_ICON = @as([*:0]const u16, @ptrFromInt(32641));
const IDC_SIZENWSE = @as([*:0]const u16, @ptrFromInt(32642));
const IDC_SIZENESW = @as([*:0]const u16, @ptrFromInt(32643));
const IDC_SIZEWE = @as([*:0]const u16, @ptrFromInt(32644));
const IDC_SIZENS = @as([*:0]const u16, @ptrFromInt(32645));
const IDC_SIZEALL = @as([*:0]const u16, @ptrFromInt(32646));
const IDC_NO = @as([*:0]const u16, @ptrFromInt(32648));
const IDC_HAND = @as([*:0]const u16, @ptrFromInt(32649));
const IDC_APPSTARTING = @as([*:0]const u16, @ptrFromInt(32650));
const IDC_HELP = @as([*:0]const u16, @ptrFromInt(32651));
const IDC_PIN = @as([*:0]const u16, @ptrFromInt(32671));
const IDC_PERSON = @as([*:0]const u16, @ptrFromInt(32672));

const IDI_APPLICATION = @as([*:0]const u16, @ptrFromInt(32512));
const IDI_HAND = @as([*:0]const u16, @ptrFromInt(32513));
const IDI_QUESTION = @as([*:0]const u16, @ptrFromInt(32514));
const IDI_EXCLAMATION = @as([*:0]const u16, @ptrFromInt(32515));
const IDI_ASTERISK = @as([*:0]const u16, @ptrFromInt(32516));
const IDI_WINLOGO = @as([*:0]const u16, @ptrFromInt(32517));
const IDI_SHIELD = @as([*:0]const u16, @ptrFromInt(32518));
const IDI_WARNING = IDI_EXCLAMATION;
const IDI_ERROR = IDI_HAND;
const IDI_INFORMATION = IDI_ASTERISK;

const IMAGE_ICON = 1;
const LR_LOADFROMFILE = 0x00000010;
const LR_DEFAULTSIZE = 0x00000040;

const CW_USEDEFAULT = @as(i32, @bitCast(@as(u32, 0x80000000)));

const NIM_ADD = 0x00000000;
const NIM_MODIFY = 0x00000001;
const NIM_DELETE = 0x00000002;
const NIM_SETFOCUS = 0x00000003;
const NIM_SETVERSION = 0x00000004;

const NIF_MESSAGE = 0x00000001;
const NIF_ICON = 0x00000002;
const NIF_TIP = 0x00000004;
const NIF_STATE = 0x00000008;
const NIF_INFO = 0x00000010;
const NIF_GUID = 0x00000020;
const NIF_REALTIME = 0x00000040;
const NIF_SHOWTIP = 0x00000080;

const NIIF_NONE = 0x00000000;
const NIIF_INFO = 0x00000001;
const NIIF_WARNING = 0x00000002;
const NIIF_ERROR = 0x00000003;

const EM_SETSEL = 0x00B1;
const EM_REPLACESEL = 0x00C2;
const EM_LINESCROLL = 0x00B6;
const EM_SETLIMITTEXT = 0x00C5;
const WM_SETFONT = 0x0030;
const LB_ADDSTRING = 0x0180;
const LB_RESETCONTENT = 0x0184;
const LB_SETHORIZONTALEXTENT = 0x0194;

// ------------------------------------------------------------------
// Structs not present in Zig 0.15 std library
// ------------------------------------------------------------------
const MSG = extern struct {
    hWnd: ?win.HWND,
    message: u32,
    wParam: win.WPARAM,
    lParam: win.LPARAM,
    time: u32,
    pt: win.POINT,
    lPrivate: u32,
};

const WNDCLASSEXW = extern struct {
    cbSize: u32,
    style: u32,
    lpfnWndProc: ?*const fn (win.HWND, u32, win.WPARAM, win.LPARAM) callconv(.winapi) win.LRESULT,
    cbClsExtra: i32,
    cbWndExtra: i32,
    hInstance: win.HINSTANCE,
    hIcon: ?win.HICON,
    hCursor: ?win.HCURSOR,
    hbrBackground: ?win.HBRUSH,
    lpszMenuName: ?[*:0]const u16,
    lpszClassName: ?[*:0]const u16,
    hIconSm: ?win.HICON,
};

const NOTIFYICONDATAW = extern struct {
    cbSize: u32,
    hWnd: win.HWND,
    uID: u32,
    uFlags: u32,
    uCallbackMessage: u32,
    hIcon: ?win.HICON,
    szTip: [128]u16,
    dwState: u32,
    dwStateMask: u32,
    szInfo: [256]u16,
    union1: u32,
    szInfoTitle: [64]u16,
    dwInfoFlags: u32,
    guidItem: u128,
    hBalloonIcon: ?win.HICON,
};

// ------------------------------------------------------------------
// External Win32 declarations not present in Zig 0.15 std library
// ------------------------------------------------------------------
extern "kernel32" fn GetModuleHandleW(lpModuleName: ?win.LPCWSTR) callconv(.winapi) ?win.HMODULE;
extern "user32" fn RegisterClassExW(lpwcx: *const WNDCLASSEXW) callconv(.winapi) win.ATOM;
extern "user32" fn CreateWindowExW(dwExStyle: win.DWORD, lpClassName: ?win.LPCWSTR, lpWindowName: ?win.LPCWSTR, dwStyle: win.DWORD, X: i32, Y: i32, nWidth: i32, nHeight: i32, hWndParent: ?win.HWND, hMenu: ?win.HMENU, hInstance: win.HINSTANCE, lpParam: ?win.LPVOID) callconv(.winapi) ?win.HWND;
extern "user32" fn DefWindowProcW(hWnd: win.HWND, Msg: u32, wParam: win.WPARAM, lParam: win.LPARAM) callconv(.winapi) win.LRESULT;
extern "user32" fn PostQuitMessage(nExitCode: i32) callconv(.winapi) void;
extern "user32" fn TrackPopupMenu(hMenu: win.HMENU, uFlags: u32, x: i32, y: i32, nReserved: i32, hWnd: win.HWND, prcRect: ?*const win.RECT) callconv(.winapi) win.BOOL;
extern "user32" fn SetForegroundWindow(hWnd: win.HWND) callconv(.winapi) win.BOOL;
extern "user32" fn CreatePopupMenu() callconv(.winapi) ?win.HMENU;
extern "user32" fn AppendMenuW(hMenu: win.HMENU, uFlags: u32, uIDNewItem: usize, lpNewItem: ?win.LPCWSTR) callconv(.winapi) win.BOOL;
extern "user32" fn DestroyMenu(hMenu: win.HMENU) callconv(.winapi) win.BOOL;
extern "user32" fn ShowWindow(hWnd: win.HWND, nCmdShow: i32) callconv(.winapi) win.BOOL;
extern "user32" fn UpdateWindow(hWnd: win.HWND) callconv(.winapi) win.BOOL;
extern "user32" fn GetMessageW(lpMsg: *MSG, hWnd: ?win.HWND, wMsgFilterMin: u32, wMsgFilterMax: u32) callconv(.winapi) win.BOOL;
extern "user32" fn TranslateMessage(lpMsg: *const MSG) callconv(.winapi) win.BOOL;
extern "user32" fn DispatchMessageW(lpMsg: *const MSG) callconv(.winapi) win.LRESULT;
extern "user32" fn LoadIconW(hInstance: ?win.HINSTANCE, lpIconName: win.LPCWSTR) callconv(.winapi) ?win.HICON;
extern "user32" fn LoadCursorW(hInstance: ?win.HINSTANCE, lpCursorName: win.LPCWSTR) callconv(.winapi) ?win.HCURSOR;
extern "user32" fn LoadImageW(hInstance: ?win.HINSTANCE, lpImageName: win.LPCWSTR, uType: u32, cxDesired: i32, cyDesired: i32, fuLoad: u32) callconv(.winapi) ?win.HANDLE;
extern "user32" fn DestroyIcon(hIcon: win.HICON) callconv(.winapi) win.BOOL;
extern "kernel32" fn GetModuleFileNameW(hModule: ?win.HMODULE, lpFilename: [*]u16, nSize: u32) callconv(.winapi) u32;
extern "user32" fn GetCursorPos(lpPoint: *win.POINT) callconv(.winapi) win.BOOL;
extern "user32" fn DestroyWindow(hWnd: win.HWND) callconv(.winapi) win.BOOL;
extern "user32" fn MessageBoxW(hWnd: ?win.HWND, lpText: win.LPCWSTR, lpCaption: win.LPCWSTR, uType: u32) callconv(.winapi) i32;
extern "gdi32" fn CreateSolidBrush(color: u32) callconv(.winapi) ?win.HBRUSH;
extern "shell32" fn ShellExecuteW(hwnd: ?win.HWND, lpOperation: ?[*:0]const u16, lpFile: ?[*:0]const u16, lpParameters: ?[*:0]const u16, lpDirectory: ?[*:0]const u16, nShowCmd: i32) callconv(.winapi) win.HINSTANCE;
extern "user32" fn SendMessageW(hWnd: win.HWND, Msg: u32, wParam: win.WPARAM, lParam: win.LPARAM) callconv(.winapi) win.LRESULT;
extern "user32" fn GetClientRect(hWnd: win.HWND, lpRect: *win.RECT) callconv(.winapi) win.BOOL;
extern "user32" fn MoveWindow(hWnd: win.HWND, X: i32, Y: i32, nWidth: i32, nHeight: i32, bRepaint: win.BOOL) callconv(.winapi) win.BOOL;
extern "user32" fn GetDlgItem(hDlg: win.HWND, nIDDlgItem: i32) callconv(.winapi) ?win.HWND;
extern "gdi32" fn GetStockObject(i: i32) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn GetLocalTime(lpSystemTime: *SYSTEMTIME) callconv(.winapi) void;
extern "user32" fn FindWindowW(lpClassName: ?win.LPCWSTR, lpWindowName: ?win.LPCWSTR) callconv(.winapi) ?win.HWND;

const SYSTEMTIME = extern struct {
    wYear: u16,
    wMonth: u16,
    wDayOfWeek: u16,
    wDay: u16,
    wHour: u16,
    wMinute: u16,
    wSecond: u16,
    wMilliseconds: u16,
};

const ANSI_FIXED_FONT = 11;

const Shell_NotifyIconW = @extern(*const fn (dwMessage: u32, lpData: *NOTIFYICONDATAW) callconv(.winapi) win.BOOL, .{ .name = "Shell_NotifyIconW", .library_name = "shell32" });

// ------------------------------------------------------------------
// Tray / Menu IDs
// ------------------------------------------------------------------
const WM_TRAYICON = WM_USER + 1;
const ID_TRAY_EXIT = 1001;
const ID_TRAY_LOG = 1003;
const ID_TRAY_STATUS = 1004;

// Log window IDs
const ID_LOG_EDIT = 3001;
const ID_LOG_REFRESH = 3002;
const ID_LOG_CLOSE = 3003;

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------
fn utf16Lit(comptime s: []const u8) [*:0]const u16 {
    return std.unicode.utf8ToUtf16LeStringLiteral(s);
}

fn copyUtf16ToBuffer(dst: []u16, src: [*:0]const u16) void {
    var i: usize = 0;
    while (src[i] != 0 and i < dst.len) : (i += 1) {
        dst[i] = src[i];
    }
    if (i < dst.len) dst[i] = 0;
}

fn utf8ToUtf16(allocator: std.mem.Allocator, utf8: []const u8) ![]u16 {
    var buf = try allocator.alloc(u16, utf8.len + 1);
    const len = try std.unicode.utf8ToUtf16Le(buf, utf8);
    buf[len] = 0;
    return buf;
}

fn utf16ToUtf8(allocator: std.mem.Allocator, utf16: []const u16) ![]u8 {
    var len: usize = 0;
    while (len < utf16.len and utf16[len] != 0) len += 1;
    var buf = try allocator.alloc(u8, len * 3 + 1);
    const out_len = try std.unicode.utf16LeToUtf8(buf, utf16[0..len]);
    buf[out_len] = 0;
    return buf;
}

fn asMenuHandle(val: usize) win.HMENU {
    return @ptrFromInt(val);
}

fn createUtf16Z(allocator: std.mem.Allocator, utf8: []const u8) ![]u16 {
    var buf = try allocator.alloc(u16, utf8.len + 1);
    const len = try std.unicode.utf8ToUtf16Le(buf, utf8);
    buf[len] = 0;
    return buf;
}

// ------------------------------------------------------------------
// Globals
// ------------------------------------------------------------------
var g_hwnd: ?win.HWND = null;
var g_hinstance: win.HINSTANCE = undefined;
var g_nid: NOTIFYICONDATAW = undefined;
// Guards every read/write of g_nid and its Shell_NotifyIconW calls.
// setTrayStatus/showLicenseErrorBalloon are called from the WSS client's
// network thread (via license_error.zig) while showTrayMenu runs on the GUI
// thread from wndProc -- without this, the two can interleave writes to the
// same fixed-size szTip/szInfo/szInfoTitle arrays and produce garbled text.
var g_nid_mutex = std.Thread.Mutex{};
var g_log_hwnd: ?win.HWND = null;
var g_allocator: std.mem.Allocator = undefined;
var g_app_icon: ?win.HICON = null;

// ------------------------------------------------------------------
// Main window procedure (hidden tray host)
// ------------------------------------------------------------------
fn wndProc(hWnd: win.HWND, msg: u32, wParam: win.WPARAM, lParam: win.LPARAM) callconv(.winapi) win.LRESULT {
    switch (msg) {
        WM_CREATE => {
            return 0;
        },
        WM_TRAYICON => {
            if (lParam == WM_RBUTTONUP or lParam == WM_LBUTTONUP) {
                showTrayMenu(hWnd);
            }
            return 0;
        },
        WM_COMMAND => {
            const id = @as(u16, @intCast(wParam & 0xFFFF));
            switch (id) {
                ID_TRAY_EXIT => {
                    platform.shutdown();
                    PostQuitMessage(0);
                },
                ID_TRAY_LOG => {
                    showLogWindow(hWnd);
                },
                else => {},
            }
            return 0;
        },
        WM_CLOSE => {
            _ = ShowWindow(hWnd, SW_HIDE);
            return 0;
        },
        WM_DESTROY => {
            PostQuitMessage(0);
            return 0;
        },
        else => {},
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

fn showTrayMenu(hWnd: win.HWND) void {
    // Update tooltip based on current connection state
    const connected = wss_client.isConnected();
    {
        g_nid_mutex.lock();
        defer g_nid_mutex.unlock();
        if (connected) {
            copyUtf16ToBuffer(&g_nid.szTip, utf16Lit("Linknesis Probe - Connected"));
        } else {
            copyUtf16ToBuffer(&g_nid.szTip, utf16Lit("Linknesis Probe - Disconnected"));
        }
        _ = Shell_NotifyIconW(NIM_MODIFY, &g_nid);
    }

    const hMenu = CreatePopupMenu() orelse return;
    const status_text = if (connected) "Status: Connected" else "Status: Disconnected";
    const status_w = utf8ToUtf16(g_allocator, status_text) catch null;
    if (status_w) |sw| {
        defer g_allocator.free(sw);
        // MF_GRAYED/MF_DISABLED both render dimmed text under the current
        // Windows visual style regardless of which flag is used -- themed
        // menus don't distinguish them the way classic/unthemed menus did.
        // This item has no WM_COMMAND handler (see wndProc), so leaving it
        // enabled (flag 0) is harmless -- clicking it is already a no-op --
        // and renders normal, readable text instead.
        _ = AppendMenuW(hMenu, 0, ID_TRAY_STATUS, @ptrCast(sw.ptr));
    } else {
        _ = AppendMenuW(hMenu, 0, ID_TRAY_STATUS, utf16Lit("Status: Unknown"));
    }
    _ = AppendMenuW(hMenu, MF_SEPARATOR, 0, null);
    _ = AppendMenuW(hMenu, 0, ID_TRAY_LOG, utf16Lit("View Log"));
    _ = AppendMenuW(hMenu, MF_SEPARATOR, 0, null);
    _ = AppendMenuW(hMenu, 0, ID_TRAY_EXIT, utf16Lit("Exit"));
    _ = SetForegroundWindow(hWnd);
    var pt: win.POINT = undefined;
    _ = GetCursorPos(&pt);
    _ = TrackPopupMenu(hMenu, 0, pt.x, pt.y, 0, hWnd, null);
    _ = DestroyMenu(hMenu);
}

pub fn showLicenseErrorBalloon(title: []const u8, text: []const u8) void {
    const title_w = utf8ToUtf16(g_allocator, title) catch null;
    const text_w = utf8ToUtf16(g_allocator, text) catch null;
    defer if (title_w) |t| g_allocator.free(t);
    defer if (text_w) |tx| g_allocator.free(tx);

    g_nid_mutex.lock();
    defer g_nid_mutex.unlock();
    if (title_w) |t| {
        const len = @min(t.len, g_nid.szInfoTitle.len - 1);
        @memset(&g_nid.szInfoTitle, 0);
        @memcpy(g_nid.szInfoTitle[0..len], t[0..len]);
    }
    if (text_w) |tx| {
        const len = @min(tx.len, g_nid.szInfo.len - 1);
        @memset(&g_nid.szInfo, 0);
        @memcpy(g_nid.szInfo[0..len], tx[0..len]);
    }
    g_nid.uFlags |= NIF_INFO;
    g_nid.dwInfoFlags = NIIF_ERROR;
    _ = Shell_NotifyIconW(NIM_MODIFY, &g_nid);
}

pub fn setTrayStatus(statusText: []const u8) void {
    const text = std.fmt.allocPrint(g_allocator, "Linknesis Probe - {s}", .{statusText}) catch return;
    defer g_allocator.free(text);
    const text_w = utf8ToUtf16(g_allocator, text) catch return;
    defer g_allocator.free(text_w);

    g_nid_mutex.lock();
    defer g_nid_mutex.unlock();
    const len = @min(text_w.len, g_nid.szTip.len - 1);
    @memset(&g_nid.szTip, 0);
    @memcpy(g_nid.szTip[0..len], text_w[0..len]);
    g_nid.uFlags |= NIF_TIP;
    // Clear any balloon left over from showLicenseErrorBalloon -- without
    // this, uFlags/dwInfoFlags keep carrying NIF_INFO/NIIF_ERROR forever, and
    // Windows re-pops the stale "License Error" balloon on every subsequent
    // status-only NIM_MODIFY for the rest of the process's life.
    g_nid.uFlags &= ~@as(u32, NIF_INFO);
    g_nid.dwInfoFlags = 0;
    _ = Shell_NotifyIconW(NIM_MODIFY, &g_nid);
}

// ------------------------------------------------------------------
// Log window with localized dates
// ------------------------------------------------------------------
fn logWndProc(hWnd: win.HWND, msg: u32, wParam: win.WPARAM, lParam: win.LPARAM) callconv(.winapi) win.LRESULT {
    switch (msg) {
        WM_CREATE => {
            const hEdit = CreateWindowExW(
                WS_EX_CLIENTEDGE,
                utf16Lit("EDIT"), null,
                WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
                0, 0, 700, 420,
                hWnd, asMenuHandle(ID_LOG_EDIT), g_hinstance, null,
            );
            // Set a fixed font
            const hFont = GetStockObject(ANSI_FIXED_FONT);
            if (hEdit) |he| {
                if (hFont) |f| {
                    _ = SendMessageW(he, WM_SETFONT, @intCast(@intFromPtr(f)), 1);
                }
                // Plain multiline EDIT controls default to a ~64K character
                // limit; without raising it, EM_REPLACESEL silently drops
                // everything past that limit when we insert the multi-MB log
                // tail, truncating the last line and hiding the newest
                // entries. wParam=0 removes the limit (up to 4 GB).
                _ = SendMessageW(he, EM_SETLIMITTEXT, 0, 0);
            }
            // Create refresh button
            _ = CreateWindowExW(
                0,
                utf16Lit("BUTTON"), utf16Lit("Refresh"),
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                10, 430, 80, 28,
                hWnd, asMenuHandle(ID_LOG_REFRESH), g_hinstance, null,
            );
            // Create close button
            _ = CreateWindowExW(
                0,
                utf16Lit("BUTTON"), utf16Lit("Close"),
                WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                610, 430, 80, 28,
                hWnd, asMenuHandle(ID_LOG_CLOSE), g_hinstance, null,
            );
            if (hEdit) |he| {
                refreshLogWindow(he);
            }
            return 0;
        },
        WM_SIZE => {
            const w = @as(i32, @intCast(lParam & 0xFFFF));
            const h = @as(i32, @intCast((lParam >> 16) & 0xFFFF));
            const hEdit = GetDlgItem(hWnd, ID_LOG_EDIT);
            if (hEdit) |he| {
                _ = MoveWindow(he, 0, 0, w, h - 50, 1);
            }
            const hRefresh = GetDlgItem(hWnd, ID_LOG_REFRESH);
            if (hRefresh) |hr| {
                _ = MoveWindow(hr, 10, h - 40, 80, 28, 1);
            }
            const hClose = GetDlgItem(hWnd, ID_LOG_CLOSE);
            if (hClose) |hc| {
                _ = MoveWindow(hc, w - 90, h - 40, 80, 28, 1);
            }
            return 0;
        },
        WM_COMMAND => {
            const id = @as(u16, @intCast(wParam & 0xFFFF));
            switch (id) {
                ID_LOG_REFRESH => {
                    const hEdit = GetDlgItem(hWnd, ID_LOG_EDIT);
                    if (hEdit) |he| refreshLogWindow(he);
                },
                ID_LOG_CLOSE => {
                    _ = DestroyWindow(hWnd);
                    g_log_hwnd = null;
                },
                else => {},
            }
            return 0;
        },
        WM_CLOSE => {
            _ = DestroyWindow(hWnd);
            g_log_hwnd = null;
            return 0;
        },
        else => {},
    }
    return DefWindowProcW(hWnd, msg, wParam, lParam);
}

const LOG_VIEW_MAX_BYTES = 64 * 1024; // 64 KB tail

fn readLogTailAlloc(allocator: std.mem.Allocator, path: []const u8, max_bytes: usize) ![]u8 {
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const size = try file.getEndPos();
    if (size == 0) {
        return allocator.alloc(u8, 0);
    }

    // Read the last max_bytes from the file. If the file is still smaller,
    // read the whole file.
    const read_start = if (size > max_bytes) size - max_bytes else 0;
    try file.seekTo(read_start);

    const alloc_size = if (size > max_bytes) max_bytes else size;
    var buf = try allocator.alloc(u8, alloc_size);
    errdefer allocator.free(buf);

    const read_len = try file.readAll(buf);

    // Find the first complete line in the tail. If the read started in the
    // middle of a line, skip forward to the next newline so we never show a
    // truncated first line.
    var line_start: usize = 0;
    while (line_start < read_len and buf[line_start] != '\n') : (line_start += 1) {}
    if (line_start < read_len) line_start += 1;

    // Find the last complete line. Anything after the final newline is a
    // partial line that is currently being written; drop it. If the file ends
    // with '\r\n' the last newline leaves an empty trailing segment that is
    // also skipped by the caller.
    var line_end: usize = read_len;
    if (read_len > 0 and buf[read_len - 1] != '\n') {
        var i: usize = read_len;
        while (i > line_start) {
            i -= 1;
            if (buf[i] == '\n') {
                line_end = i + 1;
                break;
            }
        }
        // If no newline was found between line_start and the end, the whole
        // tail is one partial line; return empty so we don't show garbage.
        if (line_end == read_len and line_start > 0) {
            allocator.free(buf);
            return allocator.alloc(u8, 0);
        }
    }

    const keep_len = line_end - line_start;
    if (keep_len == 0) {
        allocator.free(buf);
        return allocator.alloc(u8, 0);
    }

    if (line_start > 0) {
        var i: usize = 0;
        while (i < keep_len) : (i += 1) {
            buf[i] = buf[line_start + i];
        }
    }

    return allocator.realloc(buf, keep_len);
}

fn refreshLogWindow(hEdit: win.HWND) void {
    var log_path_buf: [512]u8 = undefined;
    const log_path = debug.getWindowsLogPath(&log_path_buf) catch {
        _ = SendMessageW(hEdit, EM_SETSEL, 0, @as(isize, -1));
        _ = SendMessageW(hEdit, EM_REPLACESEL, 0, @intCast(@intFromPtr(utf16Lit("Cannot determine log file path\r\n"))));
        return;
    };

    _ = SendMessageW(hEdit, LB_RESETCONTENT, 0, 0);
    _ = SendMessageW(hEdit, EM_SETSEL, 0, @as(isize, -1));
    _ = SendMessageW(hEdit, EM_REPLACESEL, 0, @intCast(@intFromPtr(utf16Lit("Loading...\r\n"))));

    const content = readLogTailAlloc(g_allocator, log_path, LOG_VIEW_MAX_BYTES) catch |err| {
        const msg = std.fmt.allocPrint(g_allocator, "Cannot read log file: {any}\r\n", .{err}) catch return;
        defer g_allocator.free(msg);
        const msg_w = utf8ToUtf16(g_allocator, msg) catch return;
        defer g_allocator.free(msg_w);
        _ = SendMessageW(hEdit, EM_SETSEL, 0, @as(isize, -1));
        _ = SendMessageW(hEdit, EM_REPLACESEL, 0, @intCast(@intFromPtr(msg_w.ptr)));
        return;
    };
    defer g_allocator.free(content);

    // Format each line with localized Windows date
    var lines = std.ArrayList(u8){};
    defer lines.deinit(g_allocator);
    const writer = lines.writer(g_allocator);

    var truncated = false;
    {
        const tmp = std.fs.cwd().openFile(log_path, .{}) catch null;
        if (tmp) |f| {
            defer f.close();
            const size = f.getEndPos() catch 0;
            truncated = size > LOG_VIEW_MAX_BYTES;
        }
    }
    if (truncated) {
        const notice = std.fmt.allocPrint(g_allocator, "[INFO] Showing last {d} KB of log file...\r\n", .{LOG_VIEW_MAX_BYTES / 1024}) catch null;
        if (notice) |n| {
            defer g_allocator.free(n);
            writer.writeAll(n) catch {};
        }
    }

    var it = std.mem.splitScalar(u8, content, '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        // If line starts with [HH:MM:SS], replace with localized date/time
        if (line.len > 10 and line[0] == '[' and line[3] == ':' and line[6] == ':' and line[9] == ']') {
            var st: SYSTEMTIME = undefined;
            GetLocalTime(&st);
            // Keep the original time portion but prepend localized date
            const fmt = std.fmt.allocPrint(g_allocator, "[{d:0>2}/{d:0>2}/{d} {s}] {s}\r\n", .{
                st.wMonth, st.wDay, st.wYear,
                line[1..9],
                line[10..],
            }) catch continue;
            defer g_allocator.free(fmt);
            writer.writeAll(fmt) catch {};
        } else {
            writer.writeAll(line) catch {};
            writer.writeAll("\r\n") catch {};
        }
    }

    if (lines.items.len == 0) {
        _ = SendMessageW(hEdit, EM_SETSEL, 0, @as(isize, -1));
        _ = SendMessageW(hEdit, EM_REPLACESEL, 0, @intCast(@intFromPtr(utf16Lit("(log file is empty)\r\n"))));
        return;
    }

    const lines_w = utf8ToUtf16(g_allocator, lines.items) catch return;
    defer g_allocator.free(lines_w);
    _ = SendMessageW(hEdit, EM_SETSEL, 0, @as(isize, -1));
    _ = SendMessageW(hEdit, EM_REPLACESEL, 0, @intCast(@intFromPtr(lines_w.ptr)));
    _ = SendMessageW(hEdit, EM_LINESCROLL, 0, @as(isize, 99999));
}

fn showLogWindow(parent: win.HWND) void {
    if (g_log_hwnd) |hwnd| {
        _ = SetForegroundWindow(hwnd);
        return;
    }
    g_log_hwnd = CreateWindowExW(
        WS_EX_APPWINDOW,
        utf16Lit("LinknesisLog"),
        utf16Lit("Linknesis Log"),
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT,
        720, 520,
        parent, null, g_hinstance, null,
    );
    if (g_log_hwnd) |hwnd| {
        _ = ShowWindow(hwnd, SW_SHOW);
        _ = UpdateWindow(hwnd);
    }
}

// ------------------------------------------------------------------
// Icon loading
// ------------------------------------------------------------------
fn getIconPath(allocator: std.mem.Allocator) !?[]u16 {
    var exe_path: [512]u16 = undefined;
    @memset(&exe_path, 0);
    const len = GetModuleFileNameW(null, &exe_path, exe_path.len);
    if (len == 0 or len >= exe_path.len) return null;

    const exe_utf8 = try std.unicode.utf16LeToUtf8Alloc(allocator, exe_path[0..len]);
    defer allocator.free(exe_utf8);

    const exe_dir = std.fs.path.dirname(exe_utf8) orelse return null;
    const icon_path = try std.fmt.allocPrint(allocator, "{s}\\linknesis.ico", .{exe_dir});
    defer allocator.free(icon_path);

    return try createUtf16Z(allocator, icon_path);
}

fn loadAppIcon() ?win.HICON {
    const icon_path = getIconPath(g_allocator) catch return null;
    if (icon_path) |path| {
        defer g_allocator.free(path);
        const h = LoadImageW(null, @ptrCast(path.ptr), IMAGE_ICON, 0, 0, LR_LOADFROMFILE | LR_DEFAULTSIZE);
        if (h) |handle| {
            debug.info("Loaded custom icon from file", .{});
            return @ptrCast(handle);
        }
        debug.warn("Failed to load custom icon, falling back to default", .{});
    } else {
        debug.warn("Could not determine icon path, falling back to default", .{});
    }
    return null;
}

// ------------------------------------------------------------------
// Public entry point
// ------------------------------------------------------------------
pub fn runMessageLoop() void {
    g_allocator = std.heap.page_allocator;
    g_hinstance = @ptrCast(GetModuleHandleW(null).?);

    // Load application icon from the .ico file deployed next to the executable.
    // Fall back to the stock application icon if the file is missing or unreadable.
    g_app_icon = loadAppIcon();
    const app_icon = g_app_icon orelse LoadIconW(null, IDI_APPLICATION);

    // Main invisible window class
    const wnd_class = WNDCLASSEXW{
        .cbSize = @sizeOf(WNDCLASSEXW),
        .style = 0,
        .lpfnWndProc = wndProc,
        .cbClsExtra = 0,
        .cbWndExtra = 0,
        .hInstance = g_hinstance,
        .hIcon = app_icon,
        .hCursor = LoadCursorW(null, IDC_ARROW),
        .hbrBackground = null,
        .lpszMenuName = null,
        .lpszClassName = utf16Lit("LinknesisMain"),
        .hIconSm = app_icon,
    };
    _ = RegisterClassExW(&wnd_class);

    // Log window class
    const log_class = WNDCLASSEXW{
        .cbSize = @sizeOf(WNDCLASSEXW),
        .style = CS_HREDRAW | CS_VREDRAW,
        .lpfnWndProc = logWndProc,
        .cbClsExtra = 0,
        .cbWndExtra = 0,
        .hInstance = g_hinstance,
        .hIcon = app_icon,
        .hCursor = LoadCursorW(null, IDC_ARROW),
        .hbrBackground = CreateSolidBrush(0x00FFFFFF),
        .lpszMenuName = null,
        .lpszClassName = utf16Lit("LinknesisLog"),
        .hIconSm = app_icon,
    };
    _ = RegisterClassExW(&log_class);

    g_hwnd = CreateWindowExW(
        0,
        utf16Lit("LinknesisMain"),
        utf16Lit("Linknesis"),
        0,
        0, 0, 0, 0,
        null, null, g_hinstance, null,
    );
    if (g_hwnd == null) {
        debug.err("Failed to create main window", .{});
        return;
    }

    // Tray icon
    g_nid = std.mem.zeroes(NOTIFYICONDATAW);
    g_nid.cbSize = @sizeOf(NOTIFYICONDATAW);
    g_nid.hWnd = g_hwnd.?;
    g_nid.uID = 1;
    g_nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAYICON;
    g_nid.hIcon = app_icon;
    copyUtf16ToBuffer(&g_nid.szTip, utf16Lit("Linknesis Probe"));

    // The Task Scheduler can start us very early during logon, before Explorer
    // has created the notification area. Wait for the taskbar window so the
    // tray icon actually registers instead of failing silently.
    var waited_ms: u64 = 0;
    const max_wait_ms: u64 = 30_000;
    while (FindWindowW(utf16Lit("Shell_TrayWnd"), null) == null and waited_ms < max_wait_ms) {
        std.Thread.sleep(100 * std.time.ns_per_ms);
        waited_ms += 100;
    }
    if (waited_ms > 0) {
        debug.info("Waited {d} ms for Explorer taskbar", .{waited_ms});
    }

    // Retry adding the icon a few times; early-logon race conditions can cause
    // Shell_NotifyIcon to fail even after the taskbar exists.
    var add_attempts: u32 = 0;
    const max_add_attempts: u32 = 10;
    while (add_attempts < max_add_attempts) : (add_attempts += 1) {
        if (Shell_NotifyIconW(NIM_ADD, &g_nid) != 0) {
            break;
        }
        debug.warn("Shell_NotifyIcon(NIM_ADD) failed on attempt {d}", .{add_attempts + 1});
        std.Thread.sleep(500 * std.time.ns_per_ms);
    }
    if (add_attempts >= max_add_attempts) {
        debug.err("Failed to add tray icon after {d} attempts", .{max_add_attempts});
    } else {
        debug.info("Tray icon added", .{});
    }

    // Pump messages
    var msg: MSG = undefined;
    while (GetMessageW(&msg, null, 0, 0) != 0) {
        _ = TranslateMessage(&msg);
        _ = DispatchMessageW(&msg);
    }

    // Cleanup
    _ = Shell_NotifyIconW(NIM_DELETE, &g_nid);
}

pub fn cleanupTray() void {
    if (g_hwnd != null) {
        _ = Shell_NotifyIconW(NIM_DELETE, &g_nid);
    }
    if (g_app_icon) |icon| {
        _ = DestroyIcon(icon);
        g_app_icon = null;
    }
}
