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
            'Name'           => 'John the Ripper Oracle Password Cracker (Fast Mode)',
            'Description'    => %Q{
              This module uses John the Ripper to identify weak passwords that have been
              acquired from the oracle_hashdump module. Passwords that have been successfully
              cracked are then saved as proper credentials
            },
            'Author'         =>
                [
                    'theLightCosine',
                    'hdm'
                ] ,
            'License'        => MSF_LICENSE  # JtR itself is GPLv2, but this wrapper is MSF (BSD)
        )
    )
  end

  def run
    @wordlist = Rex::Quickfile.new("jtrtmp")

    @wordlist.write( build_seed().flatten.uniq.join("\n") + "\n" )
    @wordlist.close
    crack("oracle")
    crack("oracle11g")
  end


  def crack(format)

    hashlist = Rex::Quickfile.new("jtrtmp")
    ltype= "#{format}.hashes"
    myloots = myworkspace.loots.where('ltype=?', ltype)
    unless myloots.nil? or myloots.empty?
      myloots.each do |myloot|
        begin
          oracle_array = CSV.read(myloot.path).drop(1)
        rescue Exception => e
          print_error("Unable to read #{myloot.path} \n #{e}")
        end
        oracle_array.each do |row|
          hashlist.write("#{row[0]}:#{row[1]}:#{myloot.host.address}:#{myloot.service.port}\n")
        end
      end
      hashlist.close

      print_status("HashList: #{hashlist.path}")
      print_status("Trying Wordlist: #{@wordlist.path}")
      john_crack(hashlist.path, :wordlist => @wordlist.path, :rules => 'single', :format => format)

      print_status("Trying Rule: All4...")
      john_crack(hashlist.path, :incremental => "All4", :format => format)

      print_status("Trying Rule: Digits5...")
      john_crack(hashlist.path, :incremental => "Digits5", :format => format)

      cracked = john_show_passwords(hashlist.path, format)

      print_status("#{cracked[:cracked]} hashes were cracked!")
      cracked[:users].each_pair do |k,v|
        print_good("Host: #{v[1]} Port: #{v[2]} User: #{k} Pass: #{v[0]}")
        report_auth_info(
          :host  => v[1],
          :port => v[2],
          :sname => 'oracle',
          :user => k,
          :pass => v[0]
        )
      end
    end
  end

end
