##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::JohnTheRipper

  def initialize
    super(
      'Name'            => 'John the Ripper AIX Password Cracker',
      'Description'     => %Q{
          This module uses John the Ripper to identify weak passwords that have been
        acquired from passwd files on AIX systems.
      },
      'Author'          =>
        [
          'theLightCosine',
          'hdm'
        ] ,
      'License'         => MSF_LICENSE  # JtR itself is GPLv2, but this wrapper is MSF (BSD)
    )

  end

  def run
    wordlist = Rex::Quickfile.new("jtrtmp")
    begin
      wordlist.write( build_seed().join("\n") + "\n" )
    ensure
      wordlist.close
    end

    myloots = myworkspace.loots.find(:all, :conditions => ['ltype=?', 'aix.hashes'])
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
        next
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

    print_status("Trying Format:des Wordlist: #{wordlist.path}")
    john_crack(hashlist.path, :wordlist => wordlist.path, :rules => 'single', :format => 'des')
    print_status("Trying Format:des Rule: All4...")
    john_crack(hashlist.path, :incremental => "All4", :format => 'des')
    print_status("Trying Format:des Rule: Digits5...")
    john_crack(hashlist.path, :incremental => "Digits5", :format => 'des')

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
