#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/dynldr'

module Metasm
module Gui
class XGui < DynLdr
	new_api_c <<EOS, 'libX11.so'
#define KeyPressMask                    (1L<<0)  
#define KeyReleaseMask                  (1L<<1)  
#define ButtonPressMask                 (1L<<2)  
#define ButtonReleaseMask               (1L<<3)  
#define EnterWindowMask                 (1L<<4)  
#define LeaveWindowMask                 (1L<<5)  
#define PointerMotionMask               (1L<<6)  
#define PointerMotionHintMask           (1L<<7)  
#define Button1MotionMask               (1L<<8)  
#define Button2MotionMask               (1L<<9)  
#define Button3MotionMask               (1L<<10) 
#define Button4MotionMask               (1L<<11) 
#define Button5MotionMask               (1L<<12) 
#define ButtonMotionMask                (1L<<13) 
#define KeymapStateMask                 (1L<<14)
#define ExposureMask                    (1L<<15) 
#define VisibilityChangeMask            (1L<<16) 
#define StructureNotifyMask             (1L<<17) 
#define ResizeRedirectMask              (1L<<18) 
#define SubstructureNotifyMask          (1L<<19) 
#define SubstructureRedirectMask        (1L<<20) 
#define FocusChangeMask                 (1L<<21) 
#define PropertyChangeMask              (1L<<22) 
#define ColormapChangeMask              (1L<<23) 
#define OwnerGrabButtonMask             (1L<<24) 

#define KeyPress                2
#define KeyRelease              3
#define ButtonPress             4
#define ButtonRelease           5
#define MotionNotify            6
#define EnterNotify             7
#define LeaveNotify             8
#define FocusIn                 9
#define FocusOut                10
#define KeymapNotify            11
#define Expose                  12
#define GraphicsExpose          13
#define NoExpose                14
#define VisibilityNotify        15
#define CreateNotify            16
#define DestroyNotify           17
#define UnmapNotify             18
#define MapNotify               19
#define MapRequest              20
#define ReparentNotify          21
#define ConfigureNotify         22
#define ConfigureRequest        23
#define GravityNotify           24
#define ResizeRequest           25
#define CirculateNotify         26
#define CirculateRequest        27
#define PropertyNotify          28
#define SelectionClear          29
#define SelectionRequest        30
#define SelectionNotify         31
#define ColormapNotify          32
#define ClientMessage           33
#define MappingNotify           34
#define GenericEvent            35
#define LASTEvent               36      /* must be bigger than any event # */

typedef unsigned long Atom;
typedef unsigned long Time;
typedef unsigned long XID;
struct _XDisplay;

typedef XID Colormap;
typedef struct _XDisplay Display;
typedef XID Drawable;
typedef XID Font;
typedef struct _XGC *GC;
typedef XID Pixmap;
typedef XID Window;

typedef 
struct {
	int type;
	unsigned long serial;
	int send_event;
	Display *display;
	Window window;
} XAnyEvent;
typedef 
struct {
	int type;
	unsigned long serial;
	int send_event;
	Display *display;
	Window window;
	Window root;
	Window subwindow;
	Time time;
	int x;
	int y;
	int x_root;
	int y_root;
	unsigned int state;
	unsigned int button;
	int same_screen;
} XButtonEvent;
typedef 
struct {
	int type;
	unsigned long serial;
	int send_event;
	Display *display;
	Window event;
	Window window;
	int place;
} XCirculateEvent;
typedef 
struct {
	int type;
	unsigned long serial;
	int send_event;
	Display *display;
	Window parent;
	Window window;
	int place;
} XCirculateRequestEvent;
typedef 
struct {
	int type;
	unsigned long serial;
	int send_event;
	Display *display;
	Window window;
	Atom message_type;
	int format;

	union {
		char b[20];
		short s[10];
		long l[5];
	} data;
} XClientMessageEvent;
typedef 
struct {
	int type;
	unsigned long serial;
	int send_event;
	Display *display;
	Window window;
	Colormap colormap;
	int new;
	int state;
} XColormapEvent;
typedef 
struct {
	int type;
	unsigned long serial;
	int send_event;
	Display *display;
	Window event;
	Window window;
	int x;
	int y;
	int width;
	int height;
	int border_width;
	Window above;
	int override_redirect;
} XConfigureEvent;
typedef 
struct {
	int type;
	unsigned long serial;
	int send_event;
	Display *display;
	Window parent;
	Window window;
	int x;
	int y;
	int width;
	int height;
	int border_width;
	Window above;
	int detail;
	unsigned long value_mask;
} XConfigureRequestEvent;
typedef 
struct {
	int type;
	unsigned long serial;
	int send_event;
	Display *display;
	Window parent;
	Window window;
	int x;
	int y;
	int width;
	int height;
	int border_width;
	int override_redirect;
} XCreateWindowEvent;
typedef 
struct {
	int type;
	unsigned long serial;
	int send_event;
	Display *display;
	Window window;
	Window root;
	Window subwindow;
	Time time;
	int x;
	int y;
	int x_root;
	int y_root;
	int mode;
	int detail;
	int same_screen;
	int focus;
	unsigned int state;
} XCrossingEvent;
typedef 
struct {
	int type;
	unsigned long serial;
	int send_event;
	Display *display;
	Window event;
	Window window;
} XDestroyWindowEvent;
typedef 
struct {
	int type;
	Display *display;
	XID resourceid;
	unsigned long serial;
	unsigned char error_code;
	unsigned char request_code;
	unsigned char minor_code;
} XErrorEvent;
typedef 
struct {
	int type;
	unsigned long serial;
	int send_event;
	Display *display;
	Window window;
	int x;
	int y;
	int width;
	int height;
	int count;
} XExposeEvent;
typedef 
struct {
	int type;
	unsigned long serial;
	int send_event;
	Display *display;
	Window window;
	int mode;
	int detail;
} XFocusChangeEvent;
typedef 
struct {
	int function;
	unsigned long plane_mask;
	unsigned long foreground;
	unsigned long background;
	int line_width;
	int line_style;
	int cap_style;
	int join_style;
	int fill_style;
	int fill_rule;
	int arc_mode;
	Pixmap tile;
	Pixmap stipple;
	int ts_x_origin;
	int ts_y_origin;
	Font font;
	int subwindow_mode;
	int graphics_exposures;
	int clip_x_origin;
	int clip_y_origin;
	Pixmap clip_mask;
	int dash_offset;
	char dashes;
} XGCValues;
typedef 
struct {
	int type;
	unsigned long serial;
	int send_event;
	Display *display;
	int extension;
	int evtype;
} XGenericEvent;
typedef 
struct {
	int type;
	unsigned long serial;
	int send_event;
	Display *display;
	int extension;
	int evtype;
	unsigned int cookie;
	void *data;
} XGenericEventCookie;
typedef 
struct {
	int type;
	unsigned long serial;
	int send_event;
	Display *display;
	Drawable drawable;
	int x;
	int y;
	int width;
	int height;
	int count;
	int major_code;
	int minor_code;
} XGraphicsExposeEvent;
typedef 
struct {
	int type;
	unsigned long serial;
	int send_event;
	Display *display;
	Window event;
	Window window;
	int x;
	int y;
} XGravityEvent;
typedef 
struct {
	int type;
	unsigned long serial;
	int send_event;
	Display *display;
	Window window;
	Window root;
	Window subwindow;
	Time time;
	int x;
	int y;
	int x_root;
	int y_root;
	unsigned int state;
	unsigned int keycode;
	int same_screen;
} XKeyEvent;
typedef 
struct {
	int type;
	unsigned long serial;
	int send_event;
	Display *display;
	Window window;
	char key_vector[32];
} XKeymapEvent;
typedef 
struct {
	int type;
	unsigned long serial;
	int send_event;
	Display *display;
	Window event;
	Window window;
	int override_redirect;
} XMapEvent;
typedef 
struct {
	int type;
	unsigned long serial;
	int send_event;
	Display *display;
	Window parent;
	Window window;
} XMapRequestEvent;
typedef 
struct {
	int type;
	unsigned long serial;
	int send_event;
	Display *display;
	Window window;
	int request;
	int first_keycode;
	int count;
} XMappingEvent;
typedef 
struct {
	int type;
	unsigned long serial;
	int send_event;
	Display *display;
	Window window;
	Window root;
	Window subwindow;
	Time time;
	int x;
	int y;
	int x_root;
	int y_root;
	unsigned int state;
	char is_hint;
	int same_screen;
} XMotionEvent;
typedef 
struct {
	int type;
	unsigned long serial;
	int send_event;
	Display *display;
	Drawable drawable;
	int major_code;
	int minor_code;
} XNoExposeEvent;
typedef 
struct {
	int type;
	unsigned long serial;
	int send_event;
	Display *display;
	Window window;
	Atom atom;
	Time time;
	int state;
} XPropertyEvent;
typedef 
struct {
	int type;
	unsigned long serial;
	int send_event;
	Display *display;
	Window event;
	Window window;
	Window parent;
	int x;
	int y;
	int override_redirect;
} XReparentEvent;
typedef 
struct {
	int type;
	unsigned long serial;
	int send_event;
	Display *display;
	Window window;
	int width;
	int height;
} XResizeRequestEvent;
typedef 
struct {
	int type;
	unsigned long serial;
	int send_event;
	Display *display;
	Window window;
	Atom selection;
	Time time;
} XSelectionClearEvent;
typedef 
struct {
	int type;
	unsigned long serial;
	int send_event;
	Display *display;
	Window requestor;
	Atom selection;
	Atom target;
	Atom property;
	Time time;
} XSelectionEvent;
typedef 
struct {
	int type;
	unsigned long serial;
	int send_event;
	Display *display;
	Window owner;
	Window requestor;
	Atom selection;
	Atom target;
	Atom property;
	Time time;
} XSelectionRequestEvent;
typedef 
struct {
	int type;
	unsigned long serial;
	int send_event;
	Display *display;
	Window event;
	Window window;
	int from_configure;
} XUnmapEvent;
typedef 
struct {
	int type;
	unsigned long serial;
	int send_event;
	Display *display;
	Window window;
	int state;
} XVisibilityEvent;

union _XEvent {
	int type;
	XAnyEvent xany;
	XKeyEvent xkey;
	XButtonEvent xbutton;
	XMotionEvent xmotion;
	XCrossingEvent xcrossing;
	XFocusChangeEvent xfocus;
	XExposeEvent xexpose;
	XGraphicsExposeEvent xgraphicsexpose;
	XNoExposeEvent xnoexpose;
	XVisibilityEvent xvisibility;
	XCreateWindowEvent xcreatewindow;
	XDestroyWindowEvent xdestroywindow;
	XUnmapEvent xunmap;
	XMapEvent xmap;
	XMapRequestEvent xmaprequest;
	XReparentEvent xreparent;
	XConfigureEvent xconfigure;
	XGravityEvent xgravity;
	XResizeRequestEvent xresizerequest;
	XConfigureRequestEvent xconfigurerequest;
	XCirculateEvent xcirculate;
	XCirculateRequestEvent xcirculaterequest;
	XPropertyEvent xproperty;
	XSelectionClearEvent xselectionclear;
	XSelectionRequestEvent xselectionrequest;
	XSelectionEvent xselection;
	XColormapEvent xcolormap;
	XClientMessageEvent xclient;
	XMappingEvent xmapping;
	XErrorEvent xerror;
	XKeymapEvent xkeymap;
	XGenericEvent xgeneric;
	XGenericEventCookie xcookie;
	long pad[24];
};


typedef union _XEvent XEvent;

int XCloseDisplay(Display*);
Window XCreateSimpleWindow(Display*, Window, int, int, unsigned int, unsigned int, unsigned int, unsigned long, unsigned long);
int XDestroyWindow(Display*, Window);
Display *XOpenDisplay(const char*);
int XSelectInput(Display*, Window, long);
int XSetForeground(Display*, GC, unsigned long);
int XStoreName(Display*, Window, const char*);
GC XCreateGC(Display*, Drawable, unsigned long, XGCValues*);
int XNextEvent(Display*, XEvent*);
int XDefaultScreen(Display*);
int XDefaultRootWindow(Display*);
int XRootWindow(Display*, int);
int XDefaultColormap(Display*, int);
int XBlackPixel(Display*, int);
int XWhitePixel(Display*, int);
int XMapWindow(Display*, Window);
int XFillRectangle(Display*, Window, GC, int, int, int, int);
int XDrawLine(Display*, Window, GC, int, int, int, int);
int XDrawString(Display*, Drawable, GC, int, int, const char*, int);
int XLookupKeysym(XEvent*, int);
EOS

def self.test
	d = xopendisplay(nil)
	s = xdefaultscreen(d)
	cmap = xdefaultcolormap(d, s)
	w = xcreatesimplewindow(d, xdefaultrootwindow(d), 0, 0, 28, 28, 0, xblackpixel(d, s), xblackpixel(d, s))
	xstorename(d, w, "lol")
	gc = xcreategc(d, w, 0, 0)
	xsetforeground(d, gc, xwhitepixel(d, s))
	xselectinput(d, w, EXPOSUREMASK|KEYPRESSMASK|BUTTONPRESSMASK)
	xmapwindow(d, w)
	msg = alloc_c_struct('XEvent')
str = 'llllmmmml'
x = 12
y = 20
	loop {
		xnextevent(d, msg)
		case msg['type']
		when EXPOSE
			#xsetforeground(d, gc, col)
			#xdrawrectangle(d, w, gc, x, y+8, 30, 30)
			xfillrectangle(d, w, gc, x, y+8, 30, 30)
			xdrawline(d, w, gc, x, y+38, x+30, y+53)
			xdrawstring(d, w, gc, x, y, str, str.length)
		when KEYPRESS
			k = xlookupkeysym(msg, 0)
			p k
		when BUTTONPRESS
			break
		end
	}
	xdestroywindow(d, w)
	xclosedisplay(d)
end

test

end
end
end

#require 'metasm/gui/dasm_main'
#require 'metasm/gui/debug'

