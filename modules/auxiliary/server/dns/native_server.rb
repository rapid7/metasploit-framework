##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/exploit/dns'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::DNS::Client
  include Msf::Exploit::Remote::DNS::Server

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Native DNS Server (Example)',
      'Description'    => %q{
        This module provides a Rex based DNS service which can store static entries,
        resolve names over pivots, and serve DNS requests across routed session comms.
        DNS tunnels can operate across the the Rex switchboard, and DNS other modules
        can use this as a template. Setting static records via hostfile allows for DNS
        spoofing attacks without direct traffic manipulation at the handlers.
      },
      'Author'         => 'RageLtMan <rageltman[at]sempervictus>',
      'License'        => MSF_LICENSE,
      'References'     => [],
      'DisclosureDate' => 'November 1987' # RFC 1035
    ))
  end

  #
  # Wrapper for service execution and cleanup
  #
  def run
    begin
      setup_server
      start_service
      while service.running?
        Rex::ThreadSafe.sleep(1)
      end
    ensure
      stop_service
    end
  end

  #
  # Creates Proc to handle incoming requests
  #
  def handle_request
    nil
  end


  #
  # Creates Proc to handle outbound responses
  #
  def handle_response
    Proc.new do |cli, data|
      cli.write(data)
    end
  end


end
