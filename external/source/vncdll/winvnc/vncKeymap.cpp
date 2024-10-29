//  Copyright (C) 2002 RealVNC Ltd. All Rights Reserved.
//  Copyright (C) 1999 AT&T Laboratories Cambridge. All Rights Reserved.
//
//  This file is part of the VNC system.
//
//  The VNC system is free software; you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation; either version 2 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program; if not, write to the Free Software
//  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,
//  USA.
//
// TightVNC distribution homepage on the Web: http://www.tightvnc.com/
//
// If the source code for the program is not available from the place from
// which you received this file, check http://www.realvnc.com/ or contact
// the authors on info@realvnc.com for information on obtaining it.

// vncKeymap.cpp

// This code originally just mapped between X keysyms and local Windows
// virtual keycodes.  Now it actually does the local-end simulation of
// key presses, to keep this messy code on one place!

// Disable warnings about truncated names caused by #include <map>
#pragma warning(disable : 4786)

#include "vncKeymap.h"

#define XK_MISCELLANY
#include "keysymdef.h"
#include "vncService.h"

#include <map>

// Mapping of X keysyms to windows VK codes.  Ordering here is the same as
// keysymdef.h to make checking easier

struct keymap_t {
  CARD32 keysym;
  CARD8 vk;
  bool extended;
};

static keymap_t keymap[] = {

  // TTY functions

  { XK_BackSpace,        VK_BACK, 0 },
  { XK_Tab,              VK_TAB, 0 },
  { XK_Clear,            VK_CLEAR, 0 },
  { XK_Return,           VK_RETURN, 0 },
  { XK_Pause,            VK_PAUSE, 0 },
  { XK_Escape,           VK_ESCAPE, 0 },
  { XK_Delete,           VK_DELETE, 1 },

  // Japanese stuff - almost certainly wrong...
  { XK_Kanji,            VK_KANJI, 0 },
  { XK_Kana_Shift,       VK_KANA, 0 },

  // Cursor control & motion

  { XK_Home,             VK_HOME, 1 },
  { XK_Left,             VK_LEFT, 1 },
  { XK_Up,               VK_UP, 1 },
  { XK_Right,            VK_RIGHT, 1 },
  { XK_Down,             VK_DOWN, 1 },
  { XK_Page_Up,          VK_PRIOR, 1 },
  { XK_Page_Down,        VK_NEXT, 1 },
  { XK_End,              VK_END, 1 },

  // Misc functions

  { XK_Select,           VK_SELECT, 0 },
  { XK_Print,            VK_SNAPSHOT, 0 },
  { XK_Execute,          VK_EXECUTE, 0 },
  { XK_Insert,           VK_INSERT, 1 },
  { XK_Help,             VK_HELP, 0 },
  { XK_Break,            VK_CANCEL, 1 },

  // Keypad Functions, keypad numbers

  { XK_KP_Space,         VK_SPACE, 0 },
  { XK_KP_Tab,           VK_TAB, 0 },
  { XK_KP_Enter,         VK_RETURN, 1 },
  { XK_KP_F1,            VK_F1, 0 },
  { XK_KP_F2,            VK_F2, 0 },
  { XK_KP_F3,            VK_F3, 0 },
  { XK_KP_F4,            VK_F4, 0 },
  { XK_KP_Home,          VK_HOME, 0 },
  { XK_KP_Left,          VK_LEFT, 0 },
  { XK_KP_Up,            VK_UP, 0 },
  { XK_KP_Right,         VK_RIGHT, 0 },
  { XK_KP_Down,          VK_DOWN, 0 },
  { XK_KP_End,           VK_END, 0 },
  { XK_KP_Page_Up,       VK_PRIOR, 0 },
  { XK_KP_Page_Down,     VK_NEXT, 0 },
  { XK_KP_Begin,         VK_CLEAR, 0 },
  { XK_KP_Insert,        VK_INSERT, 0 },
  { XK_KP_Delete,        VK_DELETE, 0 },
  // XXX XK_KP_Equal should map in the same way as ascii '='
  { XK_KP_Multiply,      VK_MULTIPLY, 0 },
  { XK_KP_Add,           VK_ADD, 0 },
  { XK_KP_Separator,     VK_SEPARATOR, 0 },
  { XK_KP_Subtract,      VK_SUBTRACT, 0 },
  { XK_KP_Decimal,       VK_DECIMAL, 0 },
  { XK_KP_Divide,        VK_DIVIDE, 1 },

  { XK_KP_0,             VK_NUMPAD0, 0 },
  { XK_KP_1,             VK_NUMPAD1, 0 },
  { XK_KP_2,             VK_NUMPAD2, 0 },
  { XK_KP_3,             VK_NUMPAD3, 0 },
  { XK_KP_4,             VK_NUMPAD4, 0 },
  { XK_KP_5,             VK_NUMPAD5, 0 },
  { XK_KP_6,             VK_NUMPAD6, 0 },
  { XK_KP_7,             VK_NUMPAD7, 0 },
  { XK_KP_8,             VK_NUMPAD8, 0 },
  { XK_KP_9,             VK_NUMPAD9, 0 },

  // Auxilliary Functions

  { XK_F1,               VK_F1, 0 },
  { XK_F2,               VK_F2, 0 },
  { XK_F3,               VK_F3, 0 },
  { XK_F4,               VK_F4, 0 },
  { XK_F5,               VK_F5, 0 },
  { XK_F6,               VK_F6, 0 },
  { XK_F7,               VK_F7, 0 },
  { XK_F8,               VK_F8, 0 },
  { XK_F9,               VK_F9, 0 },
  { XK_F10,              VK_F10, 0 },
  { XK_F11,              VK_F11, 0 },
  { XK_F12,              VK_F12, 0 },
  { XK_F13,              VK_F13, 0 },
  { XK_F14,              VK_F14, 0 },
  { XK_F15,              VK_F15, 0 },
  { XK_F16,              VK_F16, 0 },
  { XK_F17,              VK_F17, 0 },
  { XK_F18,              VK_F18, 0 },
  { XK_F19,              VK_F19, 0 },
  { XK_F20,              VK_F20, 0 },
  { XK_F21,              VK_F21, 0 },
  { XK_F22,              VK_F22, 0 },
  { XK_F23,              VK_F23, 0 },
  { XK_F24,              VK_F24, 0 },

    // Modifiers
    
  { XK_Shift_L,          VK_SHIFT, 0 },
  { XK_Shift_R,          VK_RSHIFT, 0 },
  { XK_Control_L,        VK_CONTROL, 0 },
  { XK_Control_R,        VK_CONTROL, 1 },
  { XK_Alt_L,            VK_MENU, 0 },
  { XK_Alt_R,            VK_RMENU, 1 },
};


// doKeyboardEvent wraps the system keybd_event function and attempts to find
// the appropriate scancode corresponding to the supplied virtual keycode.

inline void doKeyboardEvent(BYTE vkCode, vncServer *server, DWORD flags) {
  if (server != NULL) {
    server->SetKeyboardCounter(1);
  }
  keybd_event(vkCode, MapVirtualKey(vkCode, 0), flags, 0);
}

// KeyStateModifier is a class which helps simplify generating a "fake" press
// or release of shift, ctrl, alt, etc.  An instance of the class is created
// for every key which may need to be pressed or released.  Then either press()
// or release() may be called to make sure that the corresponding key is in the
// right state.  The destructor of the class automatically reverts to the
// previous state.

class KeyStateModifier {
public:
  KeyStateModifier(int vkCode_, vncServer *server_, int flags_=0)
    : vkCode(vkCode_), flags(flags_), server(server_),
      pressed(false), released(false)
  {}
  void press() {
    if (!(GetAsyncKeyState(vkCode) & 0x8000)) {
      doKeyboardEvent(vkCode, server, flags);

      pressed = true;
    }
  }
  void release() {
    if (GetAsyncKeyState(vkCode) & 0x8000) {
      doKeyboardEvent(vkCode, server, flags | KEYEVENTF_KEYUP);

      released = true;
    }
  }
  ~KeyStateModifier() {
    if (pressed) {
      doKeyboardEvent(vkCode, server, flags | KEYEVENTF_KEYUP);

    } else if (released) {
      doKeyboardEvent(vkCode, server, flags);

    }
  }
  int vkCode;
  int flags;
  bool pressed;
  bool released;
private:
  vncServer *server;
};

// Keymapper - a single instance of this class is used to generate Windows key
// events.

class Keymapper {

public:
  Keymapper()
  {
    for (int i = 0; i < sizeof(keymap) / sizeof(keymap_t); i++) {
      vkMap[keymap[i].keysym] = keymap[i].vk;
      extendedMap[keymap[i].keysym] = keymap[i].extended;
    }
  }

  void keyEvent(CARD32 keysym, bool down, vncServer *server)
  {
    if ((keysym >= 32 && keysym <= 126) ||
        (keysym >= 160 && keysym <= 255))
    {
      // ordinary Latin-1 character

      SHORT s = VkKeyScan((CHAR)keysym);
      if (s == -1) {

        return;
      }

      BYTE vkCode = LOBYTE(s);

      KeyStateModifier ctrl(VK_CONTROL, server);
      KeyStateModifier alt(VK_MENU, server);
      KeyStateModifier shift(VK_SHIFT, server);
      KeyStateModifier lshift(VK_LSHIFT, server);
      KeyStateModifier rshift(VK_RSHIFT, server);

      if (down) {
        BYTE modifierState = HIBYTE(s);
        if (modifierState & 2) ctrl.press();
        if (modifierState & 4) alt.press();
        if (modifierState & 1) {
          shift.press(); 
        } else {
          if (vncService::IsWin95()) {
            shift.release();
          } else {
            lshift.release();
            rshift.release();
          }
        }
      }

      doKeyboardEvent(vkCode, server, down ? 0 : KEYEVENTF_KEYUP);

    } else {

      // see if it's a recognised keyboard key, otherwise ignore it

      if (vkMap.find(keysym) == vkMap.end()) {

        return;
      }
      BYTE vkCode = vkMap[keysym];
      DWORD flags = 0;
      if (extendedMap[keysym]) flags |= KEYEVENTF_EXTENDEDKEY;
      if (!down) flags |= KEYEVENTF_KEYUP;


      if (down && (vkCode == VK_DELETE) &&
          ((GetAsyncKeyState(VK_CONTROL) & 0x8000) != 0) &&
          ((GetAsyncKeyState(VK_MENU) & 0x8000) != 0) &&
          vncService::IsWinNT())
      {
        vncService::SimulateCtrlAltDel();
        return;
      }

      if (vncService::IsWin95()) {
        switch (vkCode) {
        case VK_RSHIFT:   vkCode = VK_SHIFT;   break;
        case VK_RCONTROL: vkCode = VK_CONTROL; break;
        case VK_RMENU:    vkCode = VK_MENU;    break;
        }
      }

      doKeyboardEvent(vkCode, server, flags);
    }
  }

private:
  std::map<CARD32,CARD8> vkMap;
  std::map<CARD32,bool> extendedMap;
} key_mapper;

void vncKeymap::keyEvent(CARD32 keysym, bool down, vncServer *server)
{
  key_mapper.keyEvent(keysym, down, server);
}



void
SetShiftState(BYTE key, BOOL down)
{
	BOOL keystate = (GetAsyncKeyState(key) & 0x8000) != 0;

	// This routine sets the specified key to the desired value (up or down)
	if ((keystate && down) || ((!keystate) && (!down)))
		return;


	// Now send a key event to set the key to the new value
	doKeyboardEvent(key, NULL, down ? 0 : KEYEVENTF_KEYUP);
	keystate = (GetAsyncKeyState(key) & 0x8000) != 0;

}

void
vncKeymap::ClearShiftKeys()
{
	if (vncService::IsWinNT())
	{
		// On NT, clear both sets of keys

		// LEFT
		SetShiftState(VK_LSHIFT, FALSE);
		SetShiftState(VK_LCONTROL, FALSE);
		SetShiftState(VK_LMENU, FALSE);

		// RIGHT
		SetShiftState(VK_RSHIFT, FALSE);
		SetShiftState(VK_RCONTROL, FALSE);
		SetShiftState(VK_RMENU, FALSE);
	}
	else
	{
		// Otherwise, we can't distinguish the keys anyway...

		// Clear the shift key states
		SetShiftState(VK_SHIFT, FALSE);
		SetShiftState(VK_CONTROL, FALSE);
		SetShiftState(VK_MENU, FALSE);
	}
}
