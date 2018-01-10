##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp

  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  @rdp_domain = ''

  def proto
    'rdp'
  end

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'           => 'RDP Login check scanner',
        'Description'    => %q(
          This module attempts to authenticate to the specified Remote Desktop Protocol port
          and determines if the user has permission to access it using xfreerdp.
        ),
        'Author'         => 'Joao Santos <norwat[at]gmail.com>',
        'References'     =>
          [
            ['URL', 'https://msdn.microsoft.com/en-us/library/cc240445.aspx']
          ],
        'License'        => MSF_LICENSE,
        'DefaultOptions' =>
          {
            'DB_ALL_CREDS'    => false,
            'BLANK_PASSWORDS' => false,
            'USER_AS_PASS'    => false
          }
      )
    )

    register_options(
      [
        Opt::RPORT(3389),
        OptString.new('DOMAIN', [false, 'AD Domain', '']),
        OptString.new('XFreeRDP', [true, 'Full path to xfreerdp', "/usr/bin/xfreerdp"])
      ]
    )
  end

  def setup
    # check if xfreerdp exists
    if !File.file?(datastore['XFreeRDP'])
      fail_with(Failure::BadConfig, 'xfreerdp was not found in the specified path')
    end

    # if domain is not set then remove it from the CLI arguments to xfreerdp
    if datastore['DOMAIN'] == ''
      @rdp_domain = ""
    else
      @rdp_domain = "/v:#{datastore['DOMAIN']}"
    end

    print_status("Started RDP login scan")
  end

  def run_host(ip)
    begin
      cred_collection = Metasploit::Framework::CredentialCollection.new(
          blank_passwords: datastore['BLANK_PASSWORDS'],
          pass_file: datastore['PASS_FILE'],
          password: datastore['PASSWORD'],
          user_file: datastore['USER_FILE'],
          userpass_file: datastore['USERPASS_FILE'],
          username: datastore['USERNAME'],
          user_as_pass: datastore['USER_AS_PASS'],
          prepended_creds: anonymous_creds
      )
      cred_collection = prepend_db_passwords(cred_collection)

      scanner = system("#{datastore['XFreeRDP']} /v:#{ip}:#{rport.to_s} /u:#{cred_collection.username} /p:#{cred_collection.password} #{@rdp_domain} /cert-ignore /auth-only > /dev/null 2>&1")
      credential_data = {}
      credential_data.merge!(
          module_fullname: self.fullname,
          workspace_id: myworkspace_id,
          address: ip,
          port: rport,
          protocol: proto
      )

      # xfreerdp returns 0 if the auth was successfull
      if scanner
        credential_data[:status] = Metasploit::Model::Login::Status::SUCCESSFUL
        credential_data[:private_type] = :password
        credential_core = create_credential(credential_data)
        credential_data[:core] = credential_core
        create_credential_login(credential_data)

        if datastore['BLANK_PASSWORDS']
          print_good "#{ip}:#{rport} - Login Successful: No password!"
        else
          print_good "#{ip}:#{rport} - Login Successful: #{@rdp_domain + "\\"}#{datastore['USERNAME']}:#{datastore['PASSWORD']}"
        end

        :next_user
      else
        credential_data[:status] = Metasploit::Model::Login::Status::INCORRECT
        invalidate_login(credential_data)
        vprint_error "#{ip}:#{rport} - Login failed"
      end


    rescue Exception => e
      print_error("something went wrong " + e)
      return
    end

    report_service(
      host: rhost,
      port: rport,
      proto: 'tcp',
      name: 'rdp'
    )
  end

  # Always check for anonymous access by pretending to be a browser.
  def anonymous_creds
    anon_creds = [ ]
    anon_creds
  end
end
