##
# This module requires Metasploit: https://metasploit.com/download
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
        cracked are then saved as proper credentials.
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
    cracker = new_john_cracker

    # generate our wordlist and close the file handle
    wordlist = wordlist_file
    wordlist.close
    print_status "Wordlist file written out to #{wordlist.path}"
    cracker.wordlist = wordlist.path

    cleanup_files = [wordlist.path]

    # dynamic_1506 is oracle 11/12's H field, MD5.
    ['oracle', 'dynamic_1506', 'oracle11', 'oracle12c'].each do |format|
      cracker_instance = cracker.dup
      cracker_instance.format = format

      case format
        when 'oracle'
          cracker_instance.hash_path = hash_file('des|oracle')
          cleanup_files << cracker_instance.hash_path
        when 'dynamic_1506'
          cracker_instance.hash_path = hash_file('raw-sha1|oracle11|oracle12c|dynamic_1506')
          cleanup_files << cracker_instance.hash_path
        when 'oracle11'
          cracker_instance.hash_path = hash_file('raw-sha1|oracle11')
          cleanup_files << cracker_instance.hash_path
        when 'oracle12c'
          cracker_instance.hash_path = hash_file('oracle12c')
          cleanup_files << cracker_instance.hash_path
      end

      print_status "Cracking #{format} hashes in normal wordlist mode..."
      # Turn on KoreLogic rules if the user asked for it
      if datastore['KORELOGIC']
        cracker_instance.rules = 'KoreLogicRules'
        print_status "Applying KoreLogic ruleset..."
      end
      cracker_instance.crack do |line|
        vprint_status line.chomp
      end

      print_status "Cracking #{format} hashes in single mode..."
      cracker_instance.rules = 'single'
      cracker_instance.crack do |line|
        vprint_status line.chomp
      end

      print_status "Cracked passwords this run:"
      cracker_instance.each_cracked_password do |password_line|
        password_line.chomp!
        next if password_line.blank?
        fields = password_line.split(":")
        # If we don't have an expected minimum number of fields, this is probably not a hash line
        next unless fields.count >=3
        username = fields.shift
        core_id  = fields.pop
        password = fields.join(':') # Anything left must be the password. This accounts for passwords with : in them

        # Postgres hashes always prepend the username to the password before hashing. So we strip the username back off here.
        password.gsub!(/^#{username}/,'')
        print_good "#{username}:#{password}"
        create_cracked_credential( username: username, password: password, core_id: core_id)
      end
    end
    cleanup_files.each do |f|
      File.delete(f)
    end
  end


  def hash_file(format)
    hashlist = Rex::Quickfile.new("hashes_tmp")
    framework.db.creds(workspace: myworkspace, type: 'Metasploit::Credential::NonreplayableHash').each do |core|
      if core.private.jtr_format =~ /#{format}/
        user = core.public.username
        case format
          when 'des|oracle' #oracle
            if core.private.jtr_format.start_with?('des') #aka not oracle11/12c
              hash_string = "O$#{user.upcase}##{core.private.data}"
            end
          when 'raw-sha1|oracle11|oracle12c|dynamic_1506'
            if core.private.data =~ /H:([\dA-F]{32})/
              user = user.upcase
              hash_string = "$dynamic_1506$#{$1}"
            end
          when 'raw-sha1|oracle11'
            # this password is stored as a long ascii string with several sections
            # https://www.trustwave.com/en-us/resources/blogs/spiderlabs-blog/changes-in-oracle-database-12c-password-hashes/
            # example: S:8F2D65FB5547B71C8DA3760F10960428CD307B1C6271691FC55C1F56554A;H:DC9894A01797D91D92ECA1DA66242209;T:23D1F8CAC9001F69630ED2DD8DF67DD3BE5C470B5EA97B622F757FE102D8BF14BEDC94A3CC046D10858D885DB656DC0CBF899A79CD8C76B788744844CADE54EEEB4FDEC478FB7C7CBFBBAC57BA3EF22C
            # S: = 60 characters -> sha1(password + salt (10 bytes))
            #         40 char sha1, 20 char salt
            #         hash is 8F2D65FB5547B71C8DA3760F10960428CD307B1C
            #         salt is 6271691FC55C1F56554A
            # H: = 32 characters
            #         legacy MD5
            # T: = 160 characters
            #         PBKDF2-based SHA512 hash specific to 12C
            if core.private.data =~ /S:([\dA-F]{60})/
              hash_string = $1
            end
          when 'oracle12c'
            # see H and T sections above
            if core.private.data =~ /T:([\dA-F]{160})/
              hash_string = "$oracle12c$#{$1.downcase}"
            end
        end
        id = core.id
        hashlist.puts "#{user}:#{hash_string}:#{id}:" unless hash_string.nil? || hash_string.empty?
      end
    end
    hashlist.close
    print_status "Hashes Written out to #{hashlist.path}"
    hashlist.path
  end
end
