##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
#
##


require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::JohnTheRipper

  def initialize
    super(
      'Name'          => 'John the Ripper MySQL Password Cracker (Fast Mode)',
      'Description'   => %Q{
          This module uses John the Ripper to identify weak passwords that have been
        acquired from the mysql_hashdump module. Passwords that have been successfully
        cracked are then saved as proper credentials
      },
      'Author'         =>
        [
          'theLightCosine',
          'hdm'
        ] ,
      'License'        => MSF_LICENSE  # JtR itself is GPLv2, but this wrapper is MSF (BSD)
    )
  end

  def run
    wordlist = Rex::Quickfile.new("jtrtmp")

    wordlist.write( build_seed().flatten.uniq.join("\n") + "\n" )
    wordlist.close

    hashlist = Rex::Quickfile.new("jtrtmp")

    myloots = myworkspace.loots.where('ltype=?', 'mysql.hashes')
    unless myloots.nil? or myloots.empty?
      myloots.each do |myloot|
        begin
          mssql_array = CSV.read(myloot.path).drop(1)
        rescue Exception => e
          print_error("Unable to read #{myloot.path} \n #{e}")
        end
        mssql_array.each do |row|
          hashlist.write("#{row[0]}:#{row[1]}:#{myloot.host.address}:#{myloot.service.port}\n")
        end
      end
      hashlist.close

      print_status("HashList: #{hashlist.path}")
      print_status("Trying 'mysql-fast' Wordlist: #{wordlist.path}")
      john_crack(hashlist.path, :wordlist => wordlist.path, :rules => 'single', :format => 'mysql-fast')

      print_status("Trying 'mysql-fast' Rule: All4...")
      john_crack(hashlist.path, :incremental => "All4", :format => 'mysql-fast')

      print_status("Trying mysql-fast Rule: Digits5...")
      john_crack(hashlist.path, :incremental => "Digits5", :format => 'mysql-fast')

      cracked = john_show_passwords(hashlist.path, 'mysql-fast')

      print_status("#{cracked[:cracked]} hashes were cracked!")

      #Save cracked creds and add the passwords back to the wordlist for the next round
      tfd = ::File.open(wordlist.path, "ab")
      cracked[:users].each_pair do |k,v|
        print_good("Host: #{v[1]} Port: #{v[2]} User: #{k} Pass: #{v[0]}")
        tfd.write( v[0] + "\n" )
        report_auth_info(
          :host  => v[1],
          :port => v[2],
          :sname => 'mssql',
          :user => k,
          :pass => v[0]
        )
      end

      print_status("Trying 'mysql-sha1' Wordlist: #{wordlist.path}")
      john_crack(hashlist.path, :wordlist => wordlist.path, :rules => 'single', :format => 'mysql-sha1')

      print_status("Trying 'mysql-sha1' Rule: All4...")
      john_crack(hashlist.path, :incremental => "All4", :format => 'mysql-sha1')

      print_status("Trying 'mysql-sha1' Rule: Digits5...")
      john_crack(hashlist.path, :incremental => "Digits5", :format => 'mysql-sha1')

      cracked = john_show_passwords(hashlist.path, 'mysql-sha1')

      print_status("#{cracked[:cracked]} hashes were cracked!")

      cracked[:users].each_pair do |k,v|
        print_good("Host: #{v[1]} Port: #{v[2]} User: #{k} Pass: #{v[0]}")
        report_auth_info(
          :host  => v[1],
          :port => v[2],
          :sname => 'mssql',
          :user => k,
          :pass => v[0]
        )
      end

    end

  end


end
