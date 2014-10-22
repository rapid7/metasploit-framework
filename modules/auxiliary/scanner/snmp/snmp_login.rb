##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'metasploit/framework/community_string_collection'
require 'metasploit/framework/login_scanner/snmp'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::AuthBrute

  def initialize
    super(
      'Name'        => 'SNMP Community Scanner',
      'Description' => 'Scan for SNMP devices using common community names',
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
      Opt::CHOST,
      OptInt.new('BATCHSIZE', [true, 'The number of hosts to probe in each set', 256]),
      OptString.new('PASSWORD', [ false, 'The password to test' ]),
      OptPath.new('PASS_FILE',  [ false, "File containing communities, one per line",
        File.join(Msf::Config.data_directory, "wordlists", "snmp_default_pass.txt")
      ])
    ], self.class)

    deregister_options('USERNAME', 'USER_FILE', 'USERPASS_FILE')
  end


  # Define our batch size
  def run_batch_size
    datastore['BATCHSIZE'].to_i
  end

  # Operate on an entire batch of hosts at once
  def run_batch(batch)

    batch.each do |ip|
      collection = Metasploit::Framework::CommunityStringCollection.new(
          pass_file: datastore['PASS_FILE'],
          password: datastore['PASSWORD']
      )

      scanner = Metasploit::Framework::LoginScanner::SNMP.new(
          host: ip,
          port: rport,
          cred_details: collection,
          stop_on_success: datastore['STOP_ON_SUCCESS'],
          connection_timeout: 2
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

          print_good "#{ip}:#{rport} - LOGIN SUCCESSFUL: #{result.credential}"
        else
          invalidate_login(credential_data)
          vprint_error "#{ip}:#{rport} - LOGIN FAILED: #{result.credential} (#{result.status}: #{result.proof})"
        end
      end
    end
  end

  def rport
    datastore['RPORT']
  end




end
