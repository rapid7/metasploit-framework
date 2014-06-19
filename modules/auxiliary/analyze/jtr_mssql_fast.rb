##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'msf/core/auxiliary/jtr'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::JohnTheRipper

  def initialize
    super(
      'Name'           => 'John the Ripper MS SQL Password Cracker (Fast Mode)',
      'Description'    => %Q{
          This module uses John the Ripper to identify weak passwords that have been
        acquired from the mssql_hashdump module. Passwords that have been successfully
        cracked are then saved as proper credentials
      },
      'Author'         =>
        [
          'theLightCosine',
          'hdm'
        ],
      'License'        => MSF_LICENSE  # JtR itself is GPLv2, but this wrapper is MSF (BSD)
    )
  end

  def run
    @formats = Set.new
    cracker = new_john_cracker

    #generate our wordlist and close the file handle
    wordlist = wordlist_file
    wordlist.close
    cracker.wordlist = wordlist.path
    cracker.hash_path = hash_file

    @formats.each do |format|
      # dupe our original cracker so we can safely change options between each run
      cracker_instance = cracker.dup
      cracker_instance.format = format
      print_status "Cracking #{format} hashes in normal wordlist mode..."
      cracker_instance.crack do |line|
        print_status line.chomp
      end

      print_status "Cracking #{format} hashes in single mode..."
      cracker_instance.rules = 'single'
      cracker_instance.crack do |line|
        print_status line.chomp
      end

      print_status "Cracking #{format} hashes in incremental mode (All4)..."
      cracker_instance.rules = nil
      cracker.incremental = 'All4'
      cracker_instance.crack do |line|
        print_status line.chomp
      end

      print_status "Cracking #{format} hashes in incremental mode (Digits5)..."
      cracker.incremental = 'Digits5'
      cracker_instance.crack do |line|
        print_status line.chomp
      end

      print_status "Cracked Passwords this run:"
      cracker_instance.each_cracked_password do |password_line|
        next if password_line.blank?
        next unless password_line =~ /\w+:\w+:\d+:/
        username, password, core_id = password_line.split(':')
        create_cracked_credential( username: username, password: password, core_id: core_id)
        print_good password_line.chomp
      end
    end

  end

  def hash_file
    hashlist = Rex::Quickfile.new("hashes_tmp")
    Metasploit::Credential::NonreplayableHash.joins(:cores).where(metasploit_credential_cores: { workspace_id: myworkspace.id }, jtr_format: ['mssql', 'mssql05']).each do |hash|
      # Track the formats that we've seen so we do not attempt a format that isn't relevant
      @formats << hash.jtr_format
      hash.cores.each do |core|
        user = core.public.username
        hash_string = "0x#{hash.data}"
        id = core.id
        hashlist.puts "#{user}:#{hash_string}:#{id}:"
      end
    end
    hashlist.close
    print_status "Hashes Written out to #{hashlist.path}"
    hashlist.path
  end


end
