##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
#
##


require 'msf/core'
require 'digest/md5'

class Metasploit3 < Msf::Auxiliary

  #Included to grab the john.pot and use some utiltiy functions
  include Msf::Auxiliary::JohnTheRipper

  def initialize
    super(
      'Name'           => 'Postgres SQL md5 Password Cracker',
      'Description'    => %Q{
          This module attempts to crack Postgres SQL md5 password hashes.
        It creates hashes based on information saved in the MSF Database
        such as hostnames, usernames, passwords, and database schema information.
        The user can also supply an additional external wordlist if they wish.
      },
      'Author'         => ['theLightCosine'],
      'License'        => MSF_LICENSE
    )


    deregister_options('JOHN_BASE','JOHN_PATH')
  end

  def run

    print_status("Processing wordlist...")
    @seed= build_seed()

    print_status("Wordlist length: #{@seed.length}")

    myloots = myworkspace.loots.where('ltype=?', 'postgres.hashes')
    unless myloots.nil?
      myloots.each do |myloot|
        begin
          postgres_array = CSV.read(myloot.path).drop(1)
        rescue
          print_error("Unable to process #{myloot.path}")
        end
        postgres_array.each do |row|
          print_status("Attempting to crack hash: #{row[0]}:#{row[1]}")
          password = crack_hash(row[0],row[1])
          if password
            print_good("Username: #{row[0]} Pass: #{password}")
            report_auth_info(
              :host  => myloot.host.address,
              :port => myloot.service.port,
              :sname => 'postgres',
              :user => row[0],
              :pass => password
            )

          end
        end
      end
    end

  end

  def crack_hash(username,hash)

    @seed.each do |word|
      tmphash =  Digest::MD5.hexdigest("#{word}#{username}")
      if tmphash == hash
        return word
      end
    end

    return nil

  end



end
