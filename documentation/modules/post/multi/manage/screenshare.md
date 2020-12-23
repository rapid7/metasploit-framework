This module allows you to view and control the screen of the target computer via a local browser window. The module continually screenshots the target screen and also relays all mouse and keyboard events to session.

## Target sessions

This module only supports some target sessions, where the keyboard, mouse and screenshot API are supported.

* Windows (e.g windows/meterpreter/*)
* OSX (e.g osx/x64/meterpreter/*)
* Java (e.g java/meterpreter/*)

## Verification Steps

1. Obtain a native OSX or Windows session (or a Java session).
2. In msfconsole do `use post/multi/manage/screenshare`.
3. Set the `SESSION` option.
4. Do `run`.
5. Open the page in a javascript enabled browser


