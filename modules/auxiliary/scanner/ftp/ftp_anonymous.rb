# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Ftp
  include Msf::Auxiliary::Scanner
  include Msf::Module::Deprecated
  moved_from 'auxiliary/scanner/ftp/anonymous'

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Anonymous FTP Access Detection',
        'Description' => 'Detect anonymous (read/write) FTP service access.',
        'References' => [
          ['URL', 'https://en.wikipedia.org/wiki/File_Transfer_Protocol#Anonymous_FTP'],
          ['CVE', '1999-0497'],
        ],
        'Author' => [
          'Matteo Cantoni <goony[at]nothink.org>',
          'g0tmi1k' # @g0tmi1k - additional features
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        Opt::RPORT(21),
        OptBool.new('STORE_LOOT', [false, 'Store the directory listing as loot', true]),
        OptBool.new('EXTENDED_CHECKS', [false, 'Gather service info via FEAT, STAT and SYST', true])
      ]
    )

    # Some servers may accept anonymous login under the username `ftp` (RFC 959)
    # Some servers may also check the password is a valid email address
    deregister_options('FTPUSER', 'FTPPASS')
    datastore['FTPUSER'] = 'anonymous'
    datastore['FTPPASS'] = 'mozilla@example.com'
  end

  def run_host(target_host)
    res = connect_login(true, false)

    if res
      dir = Rex::Text.rand_text_alpha(8)
      vprint_status("Testing write access, creating test directory: #{dir}")
      # Alt would be to use STOR
      write_check = send_cmd(['MKD', dir], true)

      if write_check && write_check =~ /^2/
        access_type = 'Read/Write'
        vprint_status("Removing test directory: #{dir}")
        send_cmd(['RMD', dir], true)
      else
        access_type = 'Read-only'
      end

      print_good("Anonymous #{access_type} access (#{banner_version})")

      ftp_list_directory(username: datastore['FTPUSER'], save_loot: true) if datastore['STORE_LOOT']
      ftp_fingerprint(username: datastore['FTPUSER']) if datastore['EXTENDED_CHECKS']

      report_vuln(
        host: rhost,
        port: rport,
        proto: 'tcp',
        sname: 'ftp',
        name: 'Anonymous FTP Access',
        info: "Anonymous FTP login accepted with #{access_type} access",
        refs: references
      )
      register_creds(target_host, access_type)
    elsif banner
      print_warning("FTP service, but no anonymous access (#{banner_version})")
    else
      vprint_warning('No FTP banner received')
    end
  rescue ::Rex::ConnectionRefused
    vprint_error('Connection refused')
  rescue ::Rex::TimeoutError, ::Rex::ConnectionError, ::EOFError, ::Errno::ECONNREFUSED => e
    vprint_error(e.message)
  rescue ::Interrupt
    raise $ERROR_INFO
  ensure
    disconnect
  end

  def register_creds(target_host, access_type)
    # Build service information
    service_data = {
      address: target_host,
      port: rport,
      service_name: 'ftp',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    # Build credential information
    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      private_data: datastore['FTPPASS'],
      private_type: :password,
      username: datastore['FTPUSER'],
      workspace_id: myworkspace_id
    }

    credential_data.merge!(service_data)
    credential_core = create_credential(credential_data)

    # Assemble the options hash for creating the Metasploit::Credential::Login object
    login_data = {
      access_level: access_type,
      core: credential_core,
      last_attempted_at: DateTime.now,
      status: Metasploit::Model::Login::Status::SUCCESSFUL,
      workspace_id: myworkspace_id
    }

    login_data.merge!(service_data)
    create_credential_login(login_data)
  end
end
