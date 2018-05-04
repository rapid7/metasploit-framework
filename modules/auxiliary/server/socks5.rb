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
      'Name'        => 'Socks4a Proxy Server',
      'Description' => 'This module provides a socks5 proxy server that uses the builtin Metasploit routing to relay connections.',
      'Author'      => 'sf',
      'License'     => MSF_LICENSE,
      'Actions'     =>
        [
          [ 'Proxy' ]
        ],
      'PassiveActions' =>
        [
          'Proxy'
        ],
      'DefaultAction'  => 'Proxy'
    )

    register_options(
      [
        OptString.new( 'SRVHOST', [ true,  "The address to listen on", '0.0.0.0' ] ),
        OptPort.new( 'SRVPORT', [ true,  "The port to listen on.", 1080 ] )
      ])
  end

  def setup
    super
    @mutex = ::Mutex.new
    @socks5 = nil
  end

  def cleanup
    @mutex.synchronize do
      if( @socks5 )
        print_status( "Stopping the socks5 proxy server" )
        @socks5.stop
        @socks5 = nil
      end
    end
    super
  end

  def run
    opts = {
      'ServerHost' => datastore['SRVHOST'],
      'ServerPort' => datastore['SRVPORT'],
      'Context' => {'Msf' => framework, 'MsfExploit' => self}
    }

    @socks5 = Rex::Proto::Proxy::Socks5.new( opts )

    print_status( "Starting the socks5 proxy server" )

    @socks5.start

    @socks5.join
  end
end
