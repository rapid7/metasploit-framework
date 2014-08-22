##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::JohnTheRipper

  def initialize
    super(
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

    register_options(
      [
        OptBool.new('Crypt',[false, 'Try crypt() format hashes(Very Slow)', false])
      ]
    )

  end

  def run
    @wordlist = Rex::Quickfile.new("jtrtmp")

    begin
      @wordlist.write( build_seed().join("\n") + "\n" )
    ensure
      @wordlist.close
    end

    myloots = myworkspace.loots.where('ltype=?', 'linux.hashes')
    return if myloots.nil? or myloots.empty?

    build_hashlist(myloots)

    print_status("HashList: #{@hashlist.path}")

    try('md5')
    try('des')
    try('bsdi')
    try('crypt') if datastore['Crypt']

    cracked = john_show_passwords(@hashlist.path)

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

  def try(format)
    print_status("Trying Format:#{format} Wordlist: #{@wordlist.path}")
    john_crack(@hashlist.path, :wordlist => @wordlist.path, :rules => 'single', :format => format)
    print_status("Trying Format:#{format} Rule: All4...")
    john_crack(@hashlist.path, :incremental => "All4", :format => format)
    print_status("Trying Format:#{format} Rule: Digits5...")
    john_crack(@hashlist.path, :incremental => "Digits5", :format => format)
  end

  def build_hashlist(myloots)
    loot_data = []

    myloots.each do |myloot|
      usf = ''
      begin
        File.open(myloot.path, "rb") do |f|
          usf = f.read(f.stat.size)
        end
      rescue Exception => e
        print_error("Unable to read #{myloot.path} \n #{e}")
      end
      usf.each_line do |row|
        row.gsub!("\n", ":#{myloot.host.address}\n")
        loot_data << row
      end
    end

    @hashlist = Rex::Quickfile.new("jtrtmp")
    @hashlist.write(loot_data.join)
    @hashlist.close
  end

end
