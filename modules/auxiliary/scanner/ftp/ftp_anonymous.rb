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
      'Author' => 'Matteo Cantoni <goony[at]nothink.org>',
      'License' => MSF_LICENSE
    )

    register_options(
      [
        Opt::RPORT(21),
      ]
    )
  end

  def run_host(target_host)
    begin
      res = connect_login(true, false)

      banner.strip! if banner

      if res
        dir = Rex::Text.rand_text_alpha(8)
        vprint_status("Testing write access, Creating directory: #{dir}")
        write_check = send_cmd(['MKD', dir], true)

        if write_check && write_check =~ /^2/
          access_type = 'Read/Write'

          vprint_status("Deleting directory: #{dir}")
          send_cmd(['RMD', dir], true)
        else
          access_type = 'Read-only'
        end
        version = banner.gsub(/^\d{3}[\s-]/, '').gsub(/\A\(|\)\z/, '').strip
        print_good("Anonymous #{access_type} access (#{version})")

        report_ftp_service(banner)
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
        print_warning("FTP service, but no Anonymous access  (#{banner_version})")
        report_ftp_service(banner)
      end

      disconnect
    rescue ::Interrupt
      raise $ERROR_INFO
    rescue ::Rex::ConnectionError, ::IOError
    end
  end

  def report_ftp_service(banner)
    report_service(
      host: rhost,
      port: rport,
      proto: 'tcp',
      name: 'ftp',
      info: banner
    )
  end

  def register_creds(target_host, access_type)
    # Build service information
    service_data = {
      address: target_host,
      port: datastore['RPORT'],
      service_name: 'ftp',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    # Build credential information
    credential_data = {
      origin_type: :service,
      module_fullname: self.fullname,
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
