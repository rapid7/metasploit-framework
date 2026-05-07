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

  def initialize
    super(
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

    register_options(
      [
        Opt::RPORT(21),
        OptBool.new('STORE_LOOT', [false, 'Store the directory listing as loot', true]),
        OptBool.new('FINGERPRINT', [false, 'Gather server info via FEAT, STAT and SYST', true])
      ]
    )
  end

  def fingerprint_server(username = 'anonymous')
    print_status("Fingerprinting FTP service (as #{username})")

    [
      ['FEAT', 'ftp.cmd.feat'], # server-level
      ['STAT', 'ftp.cmd.stat'], # user-level
      ['SYST', 'ftp.cmd.syst'] # server-level
    ].each do |cmd, note_type|
      vprint_status("Sending FTP command: #{cmd}")
      response = send_cmd([cmd], true).to_s
      next if response.empty?

      response.strip.each_line.with_index do |line, i|
        prefix = i == 0 ? "FTP #{cmd}: " : '  '
        vprint_status("#{prefix}#{line.strip}")
      end

      # 215 UNIX Type: L8
      # 215 Windows_NT
      if cmd == 'SYST'
        os_name = if response.match?(/emulated/i) then nil
                  elsif response.match?(/Windows_NT/i) then 'Windows'
                  elsif response.match?(/UNIX/i) then 'Linux'
                  end
        report_host(host: rhost, os_name: os_name) if os_name
      end

      report_note(
        host: rhost,
        port: rport,
        proto: 'tcp',
        sname: 'ftp',
        type: note_type,
        data: { username: username, output: response.strip }
      )
    end
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

      if datastore['STORE_LOOT']
        vprint_status('Listing directory contents')
        listing = send_cmd_data(['LS'], nil)
        if listing.nil?
          print_warning('Could not retrieve directory listing (data connection failed)')
        elsif listing[1].nil? || listing[1].empty?
          vprint_status('Directory listing: (empty)')
        else
          vprint_status("Directory listing:\n#{listing[1]}")
          path = store_loot('ftp.anonymous', 'text/plain', rhost, listing[1], 'ftp_anonymous.txt', 'Anonymous FTP directory listing')
          print_good("Directory listing stored to: #{path}")
        end
      end

      fingerprint_server(datastore['FTPUSER']) if datastore['FINGERPRINT']

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
    report_host(host: rhost)
  rescue ::Rex::TimeoutError, ::Rex::ConnectionError, ::EOFError, ::Errno::ECONNREFUSED => e
    vprint_error(e.message)
    report_host(host: rhost)
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
