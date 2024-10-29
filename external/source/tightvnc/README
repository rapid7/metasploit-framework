
  TightVNC Java Viewer version 1.3.10

======================================================================

This distribution is based on the standard VNC source and includes new
TightVNC-specific features and fixes, such as additional low-bandwidth
optimizations, major GUI improvements, and more.

	Copyright (C) 1999 AT&T Laboratories Cambridge.
	Copyright (C) 2000 Tridia Corp.
	Copyright (C) 2002-2003 RealVNC Ltd.
	Copyright (C) 2001-2004 HorizonLive.com, Inc.
	Copyright (C) 2000-2007 Constantin Kaplinsky
	Copyright (C) 2000-2009 TightVNC Group
	All rights reserved.

This software is distributed under the GNU General Public Licence as
published by the Free Software Foundation. See the file LICENCE.TXT for the
conditions under which this software is made available. TightVNC also
contains code from other sources. See the Acknowledgements section below, and
the individual files for details of the conditions under which they are made
available.


Compiling from the sources
==========================

To compile all the .java files to .class files, simply do:

	% make all

This will also generate a JAR (Java archive) file containing all the classes. 
Most JVM (Java Virtual Machine) implementations are able to use either a set
of .class files, or the JAR archive.


Installation
============

There are three basic ways to use TightVNC Java viewer:

  1. Running applet as part of TightVNC server installation.

     Both the Unix and Windows versions of TightVNC servers include small
     built-in HTTP server which can serve Java viewer to Web clients. This
     enables easy Web access to the shared desktop without need to install
     any software on the client computer. Unix and Windows versions of
     TightVNC servers are different in the way they store the .class and .jar
     files: the Unix server (Xvnc) is able to serve any set of files present
     in a particular directory, while the Windows server (WinVNC) has all the
     .class and .jar files inside the WinVNC executable file. Therefore, for
     Xvnc, it's enough to copy the files into a correct directory, but for
     WinVNC, the server binaries should be rebuild if the built-in Java
     viewer should be updated.

     To install the Java viewer under Xvnc, copy all the .class files, the
     .jar file and the .vnc files to an installation directory (e.g.
     /usr/local/vnc/classes):

         cp *.class *.jar *.vnc /usr/local/vnc/classes

     Also, make sure that the vncserver script is configured to point to the
     installation directory (see the Xvnc manual page for the description of
     the -httpd command-line option).

  2. Running applet hosted on a standalone Web server.

     Another possibility to use the Java viewer is to install it under a
     fully-functional HTTP server such as Apache or IIS. Obviously, this
     method requires running an HTTP server, and due to the Java security
     restrictions, it's also required that the server should be installed on
     the same machine which is running the TightVNC server. In this case,
     installation is simply copying the .class and .jar files into a
     directory that is under control of the HTTP server. Also, an HTML page
     should be created which will act as a the base document for the viewer
     applet (see an example named index.html in this distribution).

     NOTE: Provided index.html page is an example only. Before using that
     file, edit it with a text editor. See more information inside
     index.html.

  3. Running the viewer as a standalone application.

     Finally, the Java viewer can be executed locally on the client machine,
     but this method requires installation of either JRE (Java Runtime
     Environment) or JDK (Java Development Kit). If all the .class files are
     in the current directory, the Java viewer can be executed like this,
     from the command line:

         java VncViewer HOST vnchost PORT 5900

     The HOST parameter is required, PORT defaults to 5900 if omitted, and
     there is a number of other optional parameters, see the Parameters
     section below.


Parameters
==========

TightVNC Java viewer supports a number of parameters allowing you to
customize its behavior. Most parameters directly correspond to the settings
found in the Options window. However, there are parameters that do not
correspond to those settings. For such parameters, you can see a note "no GUI
equivalent", in the documentation below.

Parameters can be specified in one of the two ways, depending on how the Java
viewer is used:

  1. When the Java viewer is run as an applet (embedded within an HTML
     document), parameters should be specified in the <PARAM> HTML tags,
     within the appropriate <APPLET> section. Here is an example:

    <APPLET CODE=VncViewer.class ARCHIVE=VncViewer.jar WIDTH=400 HEIGHT=300>
      <PARAM NAME="PORT" VALUE=5901>
      <PARAM NAME="Scaling factor" VALUE=50>
    </APPLET>

  2. When run as a standalone application, the Java viewer reads parameters
     from the command line. Command-line arguments should be specified in
     pairs -- first goes parameter name, then parameter value. Here is a
     command line example:

     java VncViewer HOST vnchost PORT 5901 "Scaling factor" 50

Both parameter names and their values are case-insensitive. The only
exception is the "PASSWORD" parameter, as VNC passwords are case-sensitive.

Here is the complete list of parameters supported in TightVNC Java viewer:

--> "HOST" (no GUI equivalent)

    Value: host name or IP address of the VNC server.
    Default: in applet mode, the host from which the applet was loaded.

    This parameter tells the viewer which server to connect to. It's not
    needed in the applet mode, because default Java security policy allow
    connections from applets to the only one host anyway, and that is the
    host from which the applet was loaded. However, this parameter is
    required if the viewer is used as a standalone application.

--> "PORT" (no GUI equivalent)

    Value: TCP port number on the VNC server.
    Default: 5900.

    This parameter specifies TCP port number for outgoing VNC connection.
    Note that this port is not the one used for HTTP connection from the
    browser, it is the port used for VNC/RFB connection. Usually, VNC servers
    use ports 58xx for HTTP connections, and ports 59xx for RFB connections.
    Thus, most likely, this parameter should be set to something like 5900,
    5901 etc.

--> "PASSWORD"

    Value: session password in plain text.
    Default: none, ask user.

    DO NOT EVER USE THIS PARAMETER, unless you really know what you are
    doing. It's extremely dangerous from the security point of view. When
    this parameter is set, the viewer won't ever ask for a password.

--> "ENCPASSWORD"

    Value: encrypted session password in hex-ascii.
    Default: none, ask user.

    The same as the "PASSWORD" parameter but DES-encrypted using a fixed key.
    Its value should be represented in hex-ascii e.g. "494015f9a35e8b22".
    This parameter has higher priority over the "PASSWORD" parameter. DO NOT
    EVER USE THIS PARAMETER, unless you really know what you are doing. It's
    extremely dangerous from the security point of view, and encryption does
    not actually help here since the decryption key is always known.

--> "Encoding"

    Values: "Auto", "Raw", "RRE", "CoRRE", "Hextile", "ZRLE", "Zlib", "Tight".
    Default: "Auto".

    The preferred encoding. If the value is "Auto", then the viewer will
    continuously estimate average network throughput and request encodings
    that are appropriate for current connection speed. "Hextile" is an
    encoding that was designed for fast networks, while "Tight" is better
    suited for low-bandwidth connections. From the other side, "Tight"
    decoder in the TightVNC Java viewer seems to be more efficient than
    "Hextile" decoder so it may be ok for fast networks too. "ZRLE" encoding
    is similar to "Tight", but it does not support JPEG compression and
    compression levels. Unlike "Tight" encoding, "ZRLE" is supported in
    recent versions of RealVNC products. Other encodings are not efficient
    and provided for compatibility reasons.

--> "Compression level"

    Values: "Default", "1", "2", "3", "4", "5", "6", "7", "8", "9".
    Default: "Default". ;-)

    Use specified compression level for "Tight" and "Zlib" encodings. Level 1
    uses minimum of CPU time on the server but achieves weak compression
    ratios. Level 9 offers best compression but may be slow in terms of CPU
    time consumption on the server side. Use high levels with very slow
    network connections, and low levels when working over higher-speed
    networks. The "Default" value means that the server's default compression
    level should be used.

--> "JPEG image quality"

    Values: "JPEG off", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9".
    Default: "6".

    Use the specified image quality level in "Tight" encoding. Quality level
    0 denotes bad image quality but very impressive compression ratios, while
    level 9 offers very good image quality at lower compression ratios. If
    the value is "JPEG off", the server will not use lossy JPEG compression
    in "Tight" encoding.

--> "Cursor shape updates"

    Values: "Enable", "Ignore", "Disable".
    Default: "Enable".

    Cursor shape updates is a protocol extension used to handle remote cursor
    movements locally on the client side, saving bandwidth and eliminating
    delays in mouse pointer movement. Note that current implementation of
    cursor shape updates does not allow a client to track mouse cursor
    position at the server side. This means that clients would not see mouse
    cursor movements if mouse was moved either locally on the server, or by
    another remote VNC client. Set this parameter to "Disable" if you always
    want to see real cursor position on the remote side. Setting this option
    to "Ignore" is similar to "Enable" but the remote cursor will not be
    visible at all. This can be a reasonable setting if you don't care about
    cursor shape and don't want to see two mouse cursors, one above another.

--> "Use CopyRect"

    Values: "Yes", "No".
    Default: "Yes".

    The "CopyRect" encoding saves bandwidth and drawing time when parts of
    the remote screen are moving around. Most likely, you don't want to
    change this setting.

--> "Restricted colors"

    Values: "Yes", "No".
    Default: "No".

    If set to "No", then 24-bit color format is used to represent pixel data. 
    If set to "Yes", then only 8 bits are used to represent each pixel. 8-bit
    color format can save bandwidth, but colors may look very inaccurate.

--> "Mouse buttons 2 and 3"

    Values: "Normal", "Reversed".
    Default: "Normal".

    If set to "Reversed", then right mouse button (button 2) will act as it
    was middle mouse button (button 3), and vice versa.

--> "View only"

    Values: "Yes", "No".
    Default: "No".

    If set to "Yes", then all keyboard and mouse events in the desktop window
    will be silently ignored and will not be passed to the remote side.

--> "Scale remote cursor"

    Values: "No", "50%", "75%", "125%", "150%".
    Default: "No".

    If a percentage value is specified, the remote cursor is reduced
    or enlarged accordingly. Scaling takes place only when "View only"
    is set to "No", and "Cursor shape updates" is set to "Enable".

--> "Share desktop"

    Values: "Yes", "No".
    Default: "Yes".

    Share the connection with other clients on the same VNC server. The exact
    behaviour in each case depends on the server configuration.

--> "Open new window" (no GUI equivalent, applicable only in the applet mode)

    Values: "Yes", "No".
    Default: "No".

    Operate in a separate window. This makes possible resizing the desktop,
    and adds scroll bars when necessary. If the server supports variable
    desktop size, the window will resize automatically when remote desktop
    size changes.

--> "Scaling factor" (no GUI equivalent)

    Value: an integer in the range of [1..1000], or the string "auto".
    Default: "100".

    Scale local representation of the remote desktop. The value is
    interpreted as scaling factor in percents. The default value of 100%
    corresponds to the original framebuffer size. Values below 100 reduce
    image size, values above 100 enlarge the image proportionally. If the
    parameter is set to "auto", automatic scaling is performed. Auto-scaling
    tries to choose scaling factor such way that the whole remote framebuffer
    will fit on the local screen. Currently, auto-scaling is supported only
    when the remote desktop is shown in a separate frame (always true in the
    application mode, and also in the applet mode with "Open new window"
    parameter set to "yes").

--> "Show controls" (no GUI equivalent)

    Values: "Yes", "No".
    Default: "Yes".

    Set to "No" if you want to get rid of that button panel at the top.

--> "Offer relogin" (no GUI equivalent, not applicable in the applet mode)

    Values: "Yes", "No".
    Default: "Yes".

    If set to "No", the buttons "Login again" and "Close window" won't be
    shown on disconnects or after an error has occured.

--> "Show offline desktop" (no GUI equivalent)

    Values: "Yes", "No".
    Default: "No".

    If set to "Yes", the viewer would continue to display desktop even
    if the remote side has closed the connection. In this case, if the
    button panel is enabled, then the "Disconnect" button would be
    changed to "Hide desktop" after the connection is lost.

--> "Defer screen updates" (no GUI equivalent)

    Value: time in milliseconds.
    Default: "20".

    When updating the desktop contents after receiving an update from server,
    schedule repaint within the specified number of milliseconds. Small delay
    helps to coalesce several small updates into one drawing operation,
    improving CPU usage. Set this parameter to 0 to disable deferred updates.

--> "Defer cursor updates" (no GUI equivalent)

    Value: time in milliseconds.
    Default: "10".

    When updating the desktop after moving the mouse, schedule repaint within
    the specified number of milliseconds. This setting makes sense only when
    "Cursor shape updates" parameter is set to "Enable". Small delay helps to
    coalesce several small updates into one drawing operation, improving CPU
    usage. Set this parameter to 0 to disable deferred cursor updates.

--> "Defer update requests" (no GUI equivalent)

    Value: time in milliseconds.
    Default: "0".

    After processing an update received from server, wait for the specified
    number of milliseconds before requesting next screen update. Such delay
    will end immediately on every mouse or keyboard event if not in the "view
    only" mode. Small delay helps the server to coalesce several small
    updates into one framebuffer update, improving both bandwidth and CPU
    usage. Increasing the parameter value does not affect responsiveness on
    mouse and keyboard events, but causes delays in updating the screen when
    there is no mouse and keyboard activity on the client side.

--> "SocketFactory" (no GUI equivalent)

    Value: name of the class.
    Default: none.

    This option provides the way to define an alternate I/O implementation.
    The dynamically referenced class must implement a SocketFactory
    interface, and create a Socket, as configured by this parameter. See the
    source in SocketFactory.java.

--> "DEBUG_XU" (no GUI equivalent)

    Value: non-negative integer.
    Default: 0.

    Debugging option that causes update statistics reset after the specified
    number of first framebuffer updates. This option was added to measure the
    performance of a VNC server. First few updates (especially the very first
    one) may be notably slower than others, and the viewer can exclude such
    updates from statistics.

--> "DEBUG_CU" (no GUI equivalent)

    Value: non-negative integer.
    Default: 0.

    Debugging option that causes the viewer disconnect after the specified
    number of framebuffer updates. When used with the "DEBUG_XU" parameter,
    the number of updates specified in "DEBUG_XU" is not counted as part of
    this parameter's value. E.g. if "DEBUG_XU"=2 and "DEBUG_CU"=10, then the
    viewer will disconnect after 12 framebuffer updates: update statistics
    will be reset after first two updates, then collected for next 10
    updates, then the viewer will disconnect automatically. If the value is
    0, the viewer will not disconnect automatically. This option was added to
    measure the performance of a VNC server.


RECORDING VNC SESSIONS
======================

Current version of the TightVNC Java viewer is able to record VNC (RFB)
sessions in files for later playback. The data format in saved session files
is compatible with the rfbproxy program written by Tim Waugh. Most important
thing about session recording is that it's supported only if Java security
manager allows access to local filesystem. Typically, it would not work for
unsigned applets. To use this feature, either use TightVNC Java viewer as a
standalone application (Java Runtime Environment or Java Development Kit
should be installed), or as a signed applet. The code checks if it's possible
to support session recording, and if everything's fine, the new "Record"
button should appear in the button panel. Pressing this button opens new
window which controls session recording. The GUI is pretty self-explained.

Other important facts about session recording:

--> All sessions are recorded in the 24-bit color format. If you use
    restricted colors (8-bit format), it will be temporarly switched to
    24-bit mode during session recording.

--> All sessions are recorded with cursor shape updates turned off. This is
    necessary to represent remote cursor movements in recorded sessions.

--> Closing and re-opening the recording control window does not affect the
    recording. It's not necessary to keep that window open during recording a
    session.

--> Avoid using Zlib and ZRLE encodings when recording sessions. If you have
    started recording BEFORE opening a VNC session, then you are ok. But
    otherwise, all Zlib-encoded updates will be saved Raw-encoded (that is,
    without compression at all). The case with ZRLE is even worse -- ZRLE
    updates will not be saved at all, so the resulting session file may be
    corrupted. Zlib decoding depends on the pixel data received earlier, thus
    saving the data received from the server at an arbitrary moment is not
    sufficient to decompress it correctly. And there is no way to tell Zlib
    or ZRLE decoder to reset decompressor's state -- that's a limitation of
    these encoders. The viewer could re-compress raw pixel data again before
    saving Zlib-encoded sessions, but unfortunately Java API does not allow
    to flush zlib data streams making it impossible to save Zlib-encoded RFB
    pixel data without using native code.

--> Usually, Tight encoding is the most suitable one for session recording,
    but some of the issues described above for the Zlib encoding affect the
    Tight encoding as well. Unlike Zlib sessions, Tight-encoded sessions are
    always saved Tight-encoded, but the viewer has to re-compress parts of
    data to synchronize encoder's and decoder's zlib streams. And, due to
    Java zlib API limitations, zlib streams' states have to be reset on each
    compressed rectangle, causing compression ratios to be lower than in the
    original VNC session. If you want to achieve the best possible
    performance, turn recording on BEFORE connecting to the VNC server,
    otherwise CPU usage and compression ratios may be notably less efficient.


HINTS
=====

--> To refresh remote desktop in the view-only mode, press "r" or "R"
    on the keyboard.


ACKNOWLEDGEMENTS
================

This distribution contains Java DES software by Dave Zimmerman
<dzimm@widget.com> and Jef Poskanzer <jef@acme.com>.  This is:

    Copyright (c) 1996 Widget Workshop, Inc. All Rights Reserved.

    Permission to use, copy, modify, and distribute this software and its
    documentation for NON-COMMERCIAL or COMMERCIAL purposes and without fee
    is hereby granted, provided that this copyright notice is kept intact.
    
    WIDGET WORKSHOP MAKES NO REPRESENTATIONS OR WARRANTIES ABOUT THE
    SUITABILITY OF THE SOFTWARE, EITHER EXPRESS OR IMPLIED, INCLUDING BUT
    NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
    PARTICULAR PURPOSE, OR NON-INFRINGEMENT. WIDGET WORKSHOP SHALL NOT BE
    LIABLE FOR ANY DAMAGES SUFFERED BY LICENSEE AS A RESULT OF USING,
    MODIFYING OR DISTRIBUTING THIS SOFTWARE OR ITS DERIVATIVES.
    
    THIS SOFTWARE IS NOT DESIGNED OR INTENDED FOR USE OR RESALE AS ON-LINE
    CONTROL EQUIPMENT IN HAZARDOUS ENVIRONMENTS REQUIRING FAIL-SAFE
    PERFORMANCE, SUCH AS IN THE OPERATION OF NUCLEAR FACILITIES, AIRCRAFT
    NAVIGATION OR COMMUNICATION SYSTEMS, AIR TRAFFIC CONTROL, DIRECT LIFE
    SUPPORT MACHINES, OR WEAPONS SYSTEMS, IN WHICH THE FAILURE OF THE
    SOFTWARE COULD LEAD DIRECTLY TO DEATH, PERSONAL INJURY, OR SEVERE
    PHYSICAL OR ENVIRONMENTAL DAMAGE ("HIGH RISK ACTIVITIES").  WIDGET
    WORKSHOP SPECIFICALLY DISCLAIMS ANY EXPRESS OR IMPLIED WARRANTY OF
    FITNESS FOR HIGH RISK ACTIVITIES.

    Copyright (C) 1996 by Jef Poskanzer <jef@acme.com>.  All rights
    reserved.

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions
    are met:
    1. Redistributions of source code must retain the above copyright
       notice, this list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.

    THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
    ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
    PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
    BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
    CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
    BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
    WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
    OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
    ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

    Visit the ACME Labs Java page for up-to-date versions of this and other
    fine Java utilities: http://www.acme.com/java/
