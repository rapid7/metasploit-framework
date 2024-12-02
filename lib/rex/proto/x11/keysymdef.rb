# -*- coding: binary -*-

#
# This mixin creates a lookup table for non-ascii keysym values to their keyboard mapped entries
#
# https://github.com/D-Programming-Deimos/libX11/blob/master/c/X11/keysymdef.h
# converted to printable things and in a hash for easy lookups
# another good reference: https://docs.oracle.com/cd/E67482_01/oscar/pdf/45/OnlineHelp_45/helpOnPS2keyCodes.html
# skips https://github.com/D-Programming-Deimos/libX11/blob/master/c/X11/keysymdef.h#L137-L166
#

module Rex::Proto::X11::Keysymdef
  X11KEYSYM_HASH = {
    65288 => '[BackSpace]',    # XK_BackSpace
    65289 => '[Tab]',          # XK_Tab
    65290 => '[Linefeed]',     # XK_Linefeed
    65291 => '[Clear]',        # XK_Clear
    65293 => '[Return]',       # XK_Return
    65299 => '[Pause]',        # XK_Pause
    65300 => '[Scroll_Lock]',  # XK_Scroll_Lock
    65301 => '[Sys_Req]',      # XK_Sys_Req
    65307 => '[Escape]',       # XK_Escape
    65535 => '[Delete]',       # XK_Delete
    65360 => '[Home]',         # XK_Home
    65361 => '[Left]',         # XK_Left
    65362 => '[Up]',           # XK_Up
    65363 => '[Right]',        # XK_Right
    65364 => '[Down]',         # XK_Down
    65365 => '[Prior/PageUp]', # XK_Prior
    65366 => '[Next/PageDown]', # XK_Next
    65367 => '[End]',          # XK_End
    65368 => '[Begin]',        # XK_Begin
    65376 => '[Select]',       # XK_Select
    65377 => '[Print]',        # XK_Print
    65378 => '[Execute]',      # XK_Execute
    65379 => '[Insert]',       # XK_Insert
    65381 => '[Undo]',         # XK_Undo
    65382 => '[Redo]',         # XK_Redo
    65383 => '[Menu]',         # XK_Menu
    65384 => '[Find]',         # XK_Find
    65385 => '[Cancel]',       # XK_Cancel
    65386 => '[Help]',         # XK_Help
    65387 => '[Break]',        # XK_Break
    65406 => '[Mode_switch]',  # XK_Mode_switch
    65407 => '[Num_Lock]',     # XK_Num_Lock
    65408 => '[Keypad_Space]',     # XK_KP_Space
    65417 => '[Keypad_Tab]',       # XK_KP_Tab
    65421 => '[Keypad_Enter]',     # XK_KP_Enter
    65425 => '[Keypad_F1]',        # XK_KP_F1
    65426 => '[Keypad_F2]',        # XK_KP_F2
    65427 => '[Keypad_F3]',        # XK_KP_F3
    65428 => '[Keypad_F4]',        # XK_KP_F4
    65429 => '[Keypad_Home]',      # XK_KP_Home
    65430 => '[Keypad_Left]',      # XK_KP_Left
    65431 => '[Keypad_Up]',        # XK_KP_Up
    65432 => '[Keypad_Right]',     # XK_KP_Right
    65433 => '[Keypad_Down]',      # XK_KP_Down
    65434 => '[Keypad_Prior]',     # XK_KP_Prior
    65435 => '[Keypad_Next]',      # XK_KP_Next
    65436 => '[Keypad_End]',       # XK_KP_End
    65437 => '[Keypad_Begin]',     # XK_KP_Begin
    65438 => '[Keypad_Insert]',    # XK_KP_Insert
    65439 => '[Keypad_Delete]',    # XK_KP_Delete
    65469 => '[Keypad_Equal]',     # XK_KP_Equal
    65450 => '[Keypad_Multiply]',  # XK_KP_Multiply
    65451 => '[Keypad_Add]',       # XK_KP_Add
    65452 => '[Keypad_Separator]', # XK_KP_Separator
    65453 => '[Keypad_Subtract]',  # XK_KP_Subtract
    65454 => '[Keypad_Decimal]',   # XK_KP_Decimal
    65455 => '[Keypad_Divide]',    # XK_KP_Divide
    65456 => '[Keypad_0]',         # XK_KP_0
    65457 => '[Keypad_1]',         # XK_KP_1
    65458 => '[Keypad_2]',         # XK_KP_2
    65459 => '[Keypad_3]',         # XK_KP_3
    65460 => '[Keypad_4]',         # XK_KP_4
    65461 => '[Keypad_5]',         # XK_KP_5
    65462 => '[Keypad_6]',         # XK_KP_6
    65463 => '[Keypad_7]',         # XK_KP_7
    65464 => '[Keypad_8]',         # XK_KP_8
    65465 => '[Keypad_9]',         # XK_KP_9
    65470 => '[F1]',           # XK_F1
    65471 => '[F2]',           # XK_F2
    65472 => '[F3]',           # XK_F3
    65473 => '[F4]',           # XK_F4
    65474 => '[F5]',           # XK_F5
    65475 => '[F6]',           # XK_F6
    65476 => '[F7]',           # XK_F7
    65477 => '[F8]',           # XK_F8
    65478 => '[F9]',           # XK_F9
    65479 => '[F10]',          # XK_F10
    65480 => '[F11]',          # XK_F11
    65481 => '[F12]',          # XK_F12
    65482 => '[F13]',          # XK_F13
    65483 => '[F14]',          # XK_F14
    65484 => '[F15]',          # XK_F15
    65485 => '[F16]',          # XK_F16
    65486 => '[F17]',          # XK_F17
    65487 => '[F18]',          # XK_F18
    65488 => '[F19]',          # XK_F19
    65489 => '[F20]',          # XK_F20
    65490 => '[F21]',          # XK_F21
    65491 => '[F22]',          # XK_F22
    65492 => '[F23]',          # XK_F23
    65493 => '[F24]',          # XK_F24
    65494 => '[F25]',          # XK_F25
    65495 => '[F26]',          # XK_F26
    65496 => '[F27]',          # XK_F27
    65497 => '[F28]',          # XK_F28
    65498 => '[F29]',          # XK_F29
    65499 => '[F30]',          # XK_F30
    65500 => '[F31]',          # XK_F31
    65501 => '[F32]',          # XK_F32
    65502 => '[F33]',          # XK_F33
    65503 => '[F34]',          # XK_F34
    65504 => '[F35]',            # XK_F35
    65505 => '[Shift_L]',        # XK_Shift_L
    65506 => '[Shift_R]',        # XK_Shift_R
    65507 => '[Control_L]',      # XK_Control_L
    65508 => '[Control_R]',      # XK_Control_R
    65509 => '[Caps_Lock]',      # XK_Caps_Lock
    65510 => '[Shift_Lock]',     # XK_Shift_Lock
    65511 => '[Meta_L]',         # XK_Meta_L
    65512 => '[Meta_R]',         # XK_Meta_R
    65513 => '[Alt_L]',          # XK_Alt_L
    65514 => '[Alt_R]',          # XK_Alt_R
    65515 => '[Super_L]',        # XK_Super_L
    65516 => '[Super_R]',        # XK_Super_R
    65517 => '[Hyper_L]',        # XK_Hyper_L
    65518 => '[Hyper_R]'         # XK_Hyper_R
  }
end
