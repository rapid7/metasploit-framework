require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner

    def initialize
      super(
        'Name'           => 'Kippo SSH Honeypot Detector',
        'Description'    => %q{This module will detect if an SSH server is running a Kippo
          honeypot. This is done by issuing unexpected data to the SSH service and checking
          the response returned for two particular non-standard error messages.},
        'References'  =>
          [
            [ 'URL', 'https://cultofthedyingsun.wordpress.com/2014/09/12/death-by-magick-number-fingerprinting-kippo-2014/' ],
          ],
        'Author'         => 'Andrew Morris <andrew[at]morris.guru>',
        'License'        => MSF_LICENSE
      )
    register_options(
      [
        Opt::RPORT(22)
      ], self.class)
  end

  def run_host(ip)
    connect
    banner = sock.get_once(1024)
    sock.put(banner+"\n"*8)
    response = sock.get(1024) # Not sure what the difference is between get and recv, but updated. Will look into.
    if response == "Protocol mismatch.\n" or response.include? "bad packet length 168430090" # I know this is ugly
      print_status("#{ip} - Kippo honeypot detected!") # Currently reading the report_* documentation trying to figure out how to implement properly
      end
    end
  end

