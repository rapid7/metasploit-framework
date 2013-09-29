##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
#
##


require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::JohnTheRipper

  def initialize(info={})
    super(
        update_info(
            info,
            'Name'            => 'John the Ripper Linux Password Cracker',
            'Description'     => %Q{
              This module uses John the Ripper to identify weak passwords that have been
              acquired from unshadowed passwd files from Unix systems. The module will only crack
              MD5 and DES implementations by default. Set Crypt to true to also try to crack
              Blowfish and SHA implementations. Warning: This is much slower.
            },
            'Author'          =>
                [
                    'theLightCosine',
                    'hdm'
                ] ,
            'License'         => MSF_LICENSE  # JtR itself is GPLv2, but this wrapper is MSF (BSD)
        )
    )

    register_options(
      [
        OptBool.new('Crypt',[false, 'Try crypt() format hashes(Very Slow)', false])
      ]
    )

  end

  def run
    wordlist = Rex::Quickfile.new("jtrtmp")

    begin
      wordlist.write( build_seed().join("\n") + "\n" )
    ensure
      wordlist.close
    end

    myloots = myworkspace.loots.where('ltype=?', 'linux.hashes')
    return if myloots.nil? or myloots.empty?

    loot_data = ''

    myloots.each do |myloot|
      usf = ''
      begin
        File.open(myloot.path, "rb") do |f|
          usf = f.read
        end
      rescue Exception => e
        print_error("Unable to read #{myloot.path} \n #{e}")
      end
      usf.each_line do |row|
        row.gsub!(/\n/, ":#{myloot.host.address}\n")
        loot_data << row
      end
    end

    hashlist = Rex::Quickfile.new("jtrtmp")
    hashlist.write(loot_data)
    hashlist.close

    print_status("HashList: #{hashlist.path}")

    print_status("Trying Format:md5 Wordlist: #{wordlist.path}")
    john_crack(hashlist.path, :wordlist => wordlist.path, :rules => 'single', :format => 'md5')
    print_status("Trying Format:md5 Rule: All4...")
    john_crack(hashlist.path, :incremental => "All4", :format => 'md5')
    print_status("Trying Format:md5 Rule: Digits5...")
    john_crack(hashlist.path, :incremental => "Digits5", :format => 'md5')


    print_status("Trying Format:des Wordlist: #{wordlist.path}")
    john_crack(hashlist.path, :wordlist => wordlist.path, :rules => 'single', :format => 'des')
    print_status("Trying Format:des Rule: All4...")
    john_crack(hashlist.path, :incremental => "All4", :format => 'des')
    print_status("Trying Format:des Rule: Digits5...")
    john_crack(hashlist.path, :incremental => "Digits5", :format => 'des')

    print_status("Trying Format:bsdi Wordlist: #{wordlist.path}")
    john_crack(hashlist.path, :wordlist => wordlist.path, :rules => 'single', :format => 'bsdi')
    print_status("Trying Format:bsdi Rule: All4...")
    john_crack(hashlist.path, :incremental => "All4", :format => 'bsdi')
    print_status("Trying Format:bsdi Rule: Digits5...")
    john_crack(hashlist.path, :incremental => "Digits5", :format => 'bsdi')

    if datastore['Crypt']
      print_status("Trying Format:crypt Wordlist: #{wordlist.path}")
      john_crack(hashlist.path, :wordlist => wordlist.path, :rules => 'single', :format => 'crypt')
      print_status("Trying Rule: All4...")
      john_crack(hashlist.path, :incremental => "All4", :format => 'crypt')
      print_status("Trying Rule: Digits5...")
      john_crack(hashlist.path, :incremental => "Digits5", :format => 'crypt')
    end


    cracked = john_show_passwords(hashlist.path)


    print_status("#{cracked[:cracked]} hashes were cracked!")

    cracked[:users].each_pair do |k,v|
      if v[0] == "NO PASSWORD"
        passwd=""
      else
        passwd=v[0]
      end
      print_good("Host: #{v.last}  User: #{k} Pass: #{passwd}")
      report_auth_info(
        :host  => v.last,
        :port => 22,
        :sname => 'ssh',
        :user => k,
        :pass => passwd
      )
    end
  end
end
