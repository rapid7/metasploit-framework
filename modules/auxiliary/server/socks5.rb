##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'thread'
require 'rex/proto/proxy/socks5'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'           => 'Socks5 Proxy Server',
      'Description'    => %q{
        This module provides a socks5 proxy server that uses the builtin
        Metasploit routing to relay connections.
      },
      'Author'         => [ 'sf', 'Spencer McIntyre', 'surefire' ],
      'License'        => MSF_LICENSE,
      'Actions'        =>
        [
          [ 'Proxy' ]
        ],
      'PassiveActions' =>
        [
          'Proxy'
        ],
      'DefaultAction'  => 'Proxy'
    )

    register_options([
      OptString.new('USERNAME', [false, 'Proxy username for SOCKS5 listener']),
      OptString.new('PASSWORD', [false, 'Proxy password for SOCKS5 listener']),
      OptString.new('SRVHOST',  [true,  'The address to listen on', '0.0.0.0']),
      OptPort.new('SRVPORT',    [true,  'The port to listen on', 1080])
    ])
  end

  def setup
    super
    @mutex = ::Mutex.new
    @socks_proxy = nil
  end

  def cleanup
    @mutex.synchronize do
      if @socks_proxy
        print_status('Stopping the socks5 proxy server')
        @socks_proxy.stop
        @socks_proxy = nil
      end
    end
    super
  end

  def run
    opts = {
      'ServerHost'     => datastore['SRVHOST'],
      'ServerPort'     => datastore['SRVPORT'],
      'ServerUsername' => datastore['USERNAME'],
      'ServerPassword' => datastore['PASSWORD'],
      'Context'        => {'Msf' => framework, 'MsfExploit' => self}
    }
    @socks_proxy = Rex::Proto::Proxy::Socks5::Server.new(opts)

    print_status('Starting the socks5 proxy server')
    @socks_proxy.start
    @socks_proxy.join
  end
end
