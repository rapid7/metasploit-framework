Until recently (April 2015), Meterpreter always sent string data in whatever the system encoding happened to be. With the TLV protocol, the TLV_TYPE_STRING was treated roughly as a plain C byte array, with no real expectations as to how the data should be decoded on the Meterpreter or Metasploit framework sides. As a result, type confusion occurred between different locales on remote machines and the local console. To avoid corrupting the terminal due to mistaken character encoding interpretations, Metasploit framework implements Unicode filter that converts any possibly unprintable characters into hex strings. While this allows a sufficiently-advanced human to eyeball a string for meaning, it makes dealing with Unicode strings awkward.

To solve the problem, TLV_TYPE_STRING has been retroactively declared to mean UTF-8 encoding only. All Meterpreter implementations should send UTF-8 strings and expect them in requests. On Windows systems, this means that Meterpreter needs to convert to and from Windows' UTF-16LE implementation.

So far, the Filesystem operations on all Meterpreters have been converted to expect a and send UTF-8 strings. Only the PHP meterpreter on Windows lacks Unicode support, due to limitations in PHP itself. All new TLVs should send and receive UTF-8. There is still functionality, that needs conversion beyond the Filesystem APIs, and these can be loosely discovered with a command like ```grep -R A\( *``` to find all ASCII variants of functions called by meterpreter.

In the Windows C meterpreter, there are a couple of helper functions to simplify the conversion work:

```c
wchar_t *utf8_to_wchar(const char *in);

char *wchar_to_utf8(const wchar_t *in);
```

These functions both allocate a new string as their return value, so the strings should be freed after use by the caller. Here is an example of a function expanding a path and performing the conversion to and from UTF-8:

```c
char * fs_expand_path(const char *regular)
{
        wchar_t expanded_path[FS_MAX_PATH];
        wchar_t *regular_w;

        regular_w = utf8_to_wchar(regular);
        if (regular_w == NULL) {
                return NULL;
        }

        if (ExpandEnvironmentStringsW(regular_w, expanded_path, FS_MAX_PATH) == 0) {
                free(regular_w);
                return NULL;
        }

        free(regular_w);
        return wchar_to_utf8(expanded_path);
}
```

Unicode support in Metasploit framework today is enabled by default on Linux/Unix systems, since most modern terminal emulators have no trouble displaying the characters. However, on Windows, most native terminal emulators ironically have trouble working with more than one language at once, due to historical code page support. So, for Windows, Unicode characters are still filtered by default. Setting EnableUnicodeEncoding to false will allow the native characters to be emitted by the Metasploit console.