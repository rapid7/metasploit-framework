require 'windows/api'

module Windows
  module Window
    module Menu
      API.auto_namespace = 'Windows::Window::Menu'
      API.auto_constant  = true
      API.auto_method    = true
      API.auto_unicode   = true

      private

      # Menu Flags

      MF_INSERT          = 0x00000000
      MF_CHANGE          = 0x00000080
      MF_APPEND          = 0x00000100
      MF_DELETE          = 0x00000200
      MF_REMOVE          = 0x00001000
      MF_BYCOMMAND       = 0x00000000
      MF_BYPOSITION      = 0x00000400
      MF_SEPARATOR       = 0x00000800
      MF_ENABLED         = 0x00000000
      MF_GRAYED          = 0x00000001
      MF_DISABLED        = 0x00000002
      MF_UNCHECKED       = 0x00000000
      MF_CHECKED         = 0x00000008
      MF_USECHECKBITMAPS = 0x00000200
      MF_STRING          = 0x00000000
      MF_BITMAP          = 0x00000004
      MF_OWNERDRAW       = 0x00000100
      MF_POPUP           = 0x00000010
      MF_MENUBARBREAK    = 0x00000020
      MF_MENUBREAK       = 0x00000040
      MF_UNHILITE        = 0x00000000
      MF_HILITE          = 0x00000080
      MF_DEFAULT         = 0x00001000
      MF_SYSMENU         = 0x00002000
      MF_HELP            = 0x00004000
      MF_RIGHTJUSTIFY    = 0x00004000
      MF_MOUSESELECT     = 0x00008000
      MF_END             = 0x00000080

      # System Objects

      OBJID_WINDOW            = 0x00000000
      OBJID_SYSMENU           = 0xFFFFFFFF
      OBJID_TITLEBAR          = 0xFFFFFFFE
      OBJID_MENU              = 0xFFFFFFFD
      OBJID_CLIENT            = 0xFFFFFFFC
      OBJID_VSCROLL           = 0xFFFFFFFB
      OBJID_HSCROLL           = 0xFFFFFFFA
      OBJID_SIZEGRIP          = 0xFFFFFFF9
      OBJID_CARET             = 0xFFFFFFF8
      OBJID_CURSOR            = 0xFFFFFFF7
      OBJID_ALERT             = 0xFFFFFFF6
      OBJID_SOUND             = 0xFFFFFFF5
      OBJID_QUERYCLASSNAMEIDX = 0xFFFFFFF4
      OBJID_NATIVEOM          = 0xFFFFFFF0

      API.new('AppendMenu', 'LIPP', 'B', 'user32')
      API.new('CheckMenuItem', 'LII', 'L', 'user32')
      API.new('CheckMenuRadioItem', 'LIIII', 'B', 'user32')
      API.new('CreateMenu', 'V', 'L', 'user32')
      API.new('CreatePopupMenu', 'V', 'L', 'user32')
      API.new('DeleteMenu', 'LII', 'B', 'user32')
      API.new('DestroyMenu', 'L', 'B', 'user32')
      API.new('DrawMenuBar', 'L', 'B', 'user32')
      API.new('EnableMenuItem', 'LII', 'B', 'user32')
      API.new('EndMenu', 'V', 'B', 'user32')
      API.new('GetMenu', 'L', 'L', 'user32')
      API.new('GetMenuBarInfo', 'LLLP', 'B', 'user32')
      API.new('GetMenuCheckMarkDimensions', 'V', 'L', 'user32')
      API.new('GetMenuDefaultItem', 'LII', 'I', 'user32')
      API.new('GetMenuInfo', 'LP', 'B', 'user32')
      API.new('GetMenuItemCount', 'L', 'I', 'user32')
      API.new('GetMenuItemID', 'LI', 'I', 'user32')
      API.new('GetMenuItemInfo', 'LIIP', 'B', 'user32')
      API.new('GetMenuItemRect', 'LLIP', 'B', 'user32')
      API.new('GetMenuState', 'LLI', 'I', 'user32')
      API.new('GetMenuString', 'LIPII', 'I', 'user32')
      API.new('GetSubMenu', 'LI', 'L', 'user32')
      API.new('GetSystemMenu', 'LI', 'L', 'user32')
      API.new('HiliteMenuItem', 'LLII', 'B', 'user32')
      API.new('InsertMenu', 'LIIPP', 'B', 'user32')
      API.new('InsertMenuItem', 'LIIP', 'B', 'user32')
      API.new('IsMenu', 'L', 'B', 'user32')
      API.new('LoadMenu', 'LP', 'L', 'user32')
      API.new('LoadMenuIndirect', 'P', 'L', 'user32')
      API.new('MenuItemFromPoint', 'LLP', 'I', 'user32')
      API.new('ModifyMenu', 'LIIPP', 'B', 'user32')
      API.new('RemoveMenu', 'LII', 'B', 'user32')
      API.new('SetMenu', 'LL', 'B', 'user32')
      API.new('SetMenuDefaultItem', 'LLL', 'B', 'user32')
      API.new('SetMenuInfo', 'LP', 'B', 'user32')
      API.new('SetMenuItemBitmaps', 'LIILL', 'B', 'user32')
      API.new('SetMenuItemInfo', 'LIIP', 'B', 'user32')
      API.new('TrackPopupMenu', 'LIIIILP', 'B', 'user32')
      API.new('TrackPopupMenuEx', 'LIIILP', 'B', 'user32')
    end
  end
end
