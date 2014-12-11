require 'msf/core'

class Metasploit3 < Msf::Auxiliary

        include Msf::Exploit::Remote::Tcp
        include Msf::Auxiliary::Scanner

        def initialize
                super(
                        'Name'           => 'Kippo SSH Honeypot Detector',
                        'Version'        => '$Revision: 1 $',
                        'Description'    => 'Detect if an SSH server is a Kippo honeypot',
                        'Author'         => 'Andrew Morris',
                        'License'        => MSF_LICENSE
                )
                register_options(
                        [
                                Opt::RPORT(22)
                        ], self.class)
        end

        def run_host(ip)
                connect()
                banner = sock.recv(1024)
                sock.puts("\n\n\n\n\n\n\n\n")
                response = sock.recv(1024)
                if response.include? "168430090"
                        print_status("#{ip} - Kippo honeypot detected!")
                end
                disconnect()
        end
end
