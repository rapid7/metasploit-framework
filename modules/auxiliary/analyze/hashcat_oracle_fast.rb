##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/hashcat'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Hashcat

  def initialize
    super(
      'Name'           => 'Hashcat Oracle Password Cracker (Fast Mode)',
      'Description'    => %Q{
          This module uses Hashcat to identify weak passwords that have been
        acquired from the oracle_hashdump module. Passwords that have been successfully
        cracked are then saved as proper credentials.
        oracle is format 3100 in hashcat, hashcat's format requires additional
        fields not supported.  Please use the JtR module instead for oracle.
        oracle11 is format 112 in hashcat.
        oracle12c is format 12300 in hashcat.
      },
      'Author'         => ['h00die'] ,
      'License'        => MSF_LICENSE
    )
  end

  def run
    @formats = Set.new

    cracker = new_hashcat_cracker

    # hashes is an array to re-reference after cracking
    # format: ['hash:username:id']
    # create the hash file first, so if there aren't any hashes we can quit early
    cracker.hash_path, hashes = hash_file

    # generate our wordlist and close the file handle.
    wordlist = wordlist_file
    unless wordlist
      print_error('This module cannot run without a database connected. Use db_connect to connect to a database.')
      return
    end

    wordlist.close
    print_status "Wordlist file written out to #{wordlist.path}"
    cracker.wordlist = wordlist.path

    cleanup_files = [cracker.hash_path, wordlist.path]

    @formats.each do |format|
      # dupe our original cracker so we can safely change options between each run
      cracker_instance = cracker.dup
      cracker_instance.format = jtr_format_to_hashcat_format(format)
      print_status "Cracking #{format} hashes in normal wordlist mode..."
      cracker_instance.crack do |line|
        vprint_status line.chomp
      end

      print_status "Cracking #{format} hashes in increment mode..."
      cracker_instance.wordlist = nil
      cracker_instance.attack = '3'
      cracker_instance.increment = true
      cracker_instance.crack do |line|
        vprint_status line.chomp
      end

      print_status "Cracked Passwords this run:"
      cracker_instance.each_cracked_password do |password_line|
        password_line.chomp!
        next if password_line.blank?
        fields = password_line.split(":")
        # If we don't have an expected minimum number of fields, this is probably not a hash line
        next unless fields.count >= 2
        hash = fields.shift
        if format == 'oracle11' || format == "raw-sha1,oracle"
          hash = "S:#{hash}#{fields.shift}" # we pull the first two fields, hash, and salt
        elsif format == 'oracle12c' || format == 'pbkdf2,oracle12c'
          hash = "T:#{hash}"
        end
        password = fields.join(':') # Anything left must be the password. This accounts for passwords w$
        hashes.each do |h|
          h = h.split("&&&")
          if format == 'oracle11' || format == "raw-sha1,oracle"
            # we add the ; on the end since thats when T: or H: would fall in next
            next unless h[0].downcase.start_with?("#{hash.downcase};")
          elsif format == "oracle12c" || format == 'pbkdf2,oracle12c'
            # add ; first since T is never the first part
            next unless h[0].downcase.include?(";#{hash.downcase}")
          end
          username = h[1]
          core_id  = h[2]
          print_good "#{username}:#{password}"
          create_cracked_credential( username: username, password: password, core_id: core_id)
        end
      end
    end
    if datastore['DeleteTempFiles']
      cleanup_files.each do |f|
        File.delete(f)
      end
    end
  end

  def hash_file
    hashes = []
    hashlist = Rex::Quickfile.new("hashes_tmp")
    framework.db.creds(workspace: myworkspace, type: 'Metasploit::Credential::NonreplayableHash').each do |core|
      # raw-sha1,oracle is oracle11
      if core.private.jtr_format =~ /raw-sha1,oracle|oracle11|oracle12c/
        @formats << core.private.jtr_format
        hashlist.puts hash_to_hashcat(core)
        # ':' is part of oracle hashes, so we use &&& instead
        hashes << "#{core.private.data}&&&#{core.public.username}&&&#{core.id}"
      end
    end
    hashlist.close
    print_status "Hashes Written out to #{hashlist.path}"
    return hashlist.path, hashes
  end
end
