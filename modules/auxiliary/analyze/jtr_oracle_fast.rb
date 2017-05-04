##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core/auxiliary/jtr'

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::JohnTheRipper

  def initialize
    super(
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
  end

  def run
    @wordlist = Rex::Quickfile.new("jtrtmp")

    @wordlist.write( build_seed().flatten.uniq.join("\n") + "\n" )
    @wordlist.close
    crack("oracle")
    crack("oracle11g")
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: opts[:user],
      private_data: opts[:password],
      private_type: :nonreplayable_hash,
      jtr_format: opts[:format]
    }.merge(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
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
        report_cred(
          ip: v[1],
          port: v[2],
          service_name: 'oracle',
          user: k,
          pass: v[0],
          format: format,
          proof: cracked.inspect
        )
      end
    end
  end

end
