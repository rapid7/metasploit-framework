##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'thread'
require 'msf/core'
require 'rex/proto/proxy/socks4a'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'Socks4a Proxy Server',
      'Description' => 'This module provides a socks4a proxy server that uses the builtin Metasploit routing to relay connections.',
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
      ], self.class )
  end

  def setup
    super
    @mutex = ::Mutex.new
    @socks4a = nil
  end

  def cleanup
    @mutex.synchronize do
      if( @socks4a )
        print_status( "Stopping the socks4a proxy server" )
        @socks4a.stop
        @socks4a = nil
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

    @socks4a = Rex::Proto::Proxy::Socks4a.new( opts )

    print_status( "Starting the socks4a proxy server" )

    @socks4a.start

    @socks4a.join
  end

end
