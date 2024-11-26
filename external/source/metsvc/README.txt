Meterpreter Service 1.0

  by Alexander Sotirov <asotirov@determina.com>


This is a network service wrapper for the Meterpreter. It can be used as a
Windows service, or run as a command line application.

Compilation:

    You'll need GNU make and Visual C++. Go to the src directory and run make.

Installation:

    1. Copy metsvc.exe and metsvc-server.exe from the current directory to
       the installation directory.

    2. Copy metsrv.dll from Metasploit to the installation directory.

    3. To register the Meterpreter as a windows service, go to the
       installation directory and run:

           metsvc.exe install-service

Running:

    If you registered the the Meterpreter as a Windows service, it will start
    automatically.
    
    Otherwise, you have to start it manually by running metsvc.exe


Uninstallation:

    If you registered the Meterpreter as a Windows service, you need to stop it
    and remove the service by running:

        metsvc.exe remove-service

    Then simply delete all files.

Using:

    Use test.rb to connect to the Meterpreter and run the sysinfo command:

    $./test.rb 192.168.70.12 31337

    * Initializing Meterpreter
    * Loading Stdapi
    * System info:
    {"OS"=>"Windows XP (Build 2600, Service Pack 2).", "Computer"=>"VM-WINXPPRO"}
    * Closing socket
