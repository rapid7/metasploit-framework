##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Ftp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
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
        'g0tmi1k' # @g0tmi1k // https://blog.g0tmi1k.com/ - additional features
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
        OptBool.new('STORE_LOOT', [false, 'Store the directory listing as loot', true])
      ]
    )
  end

  def sanitize_ftp_response(str)
    Rex::Text.to_hex_ascii(str.to_s.gsub(/^\d{3}[\s-]/, '').strip.gsub(/\A\(|\)\z/, ''))
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

      print_good("Anonymous #{access_type} access (#{sanitize_ftp_response(banner)})")

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
      print_warning("FTP service, but no Anonymous access (#{sanitize_ftp_response(banner)})")
    else
      vprint_warning('No FTP banner received')
    end

    report_ftp_service
  rescue ::Rex::TimeoutError, ::Rex::ConnectionError, ::EOFError, ::Errno::ECONNREFUSED => e
    vprint_error(e.message)
    report_host(host: rhost)
  rescue ::Interrupt
    raise $ERROR_INFO
  ensure
    disconnect
  end

  def report_ftp_service
    report_service(
      host: rhost,
      port: rport,
      proto: 'tcp',
      name: 'ftp',
      info: sanitize_ftp_response(banner)
    )
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
