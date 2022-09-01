# include/windows
The files within this directory are useful to avoid boiler plate code that is often necessary in Windows exploits.

## common.h
This file provides the convenient `dprintf` method to easily allow debug output to be toggled on and off through the
`DEBUGTRACE` macro definition.

## definitions.h
This files includes general Windows definitions of common (but undocumented) structures and function signatures such as
those found within NTDLL.
