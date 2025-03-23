##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::PasswordCracker

  def initialize
    super(
      'Name' => 'Apply Pot File To Hashes',
      'Description' => %(
          This module uses a John the Ripper or Hashcat .pot file to crack any password
        hashes in the creds database instantly.  JtR's --show functionality is used to
        help combine all the passwords into an easy to use format.
      ),
      'Author' => ['h00die'],
      'License' => MSF_LICENSE,
      'Actions' => [
        ['john', { 'Description' => 'Use John the Ripper' }],
        # ['hashcat', 'Description' => 'Use Hashcat'], # removed for simplicity
      ],
      'DefaultAction' => 'john',
    )
    deregister_options('ITERATION_TIMEOUT')
    deregister_options('CUSTOM_WORDLIST')
    deregister_options('KORELOGIC')
    deregister_options('MUTATE')
    deregister_options('USE_CREDS')
    deregister_options('USE_DB_INFO')
    deregister_options('USE_DEFAULT_WORDLIST')
    deregister_options('USE_ROOT_WORDS')
    deregister_options('USE_HOSTNAMES')
  end

  # Not all hash formats include an 'id' field, which corresponds which db entry
  # an item is to its hash.  This can be problematic, especially when a username
  # is used as a salt.  Due to all the variations, we make a small HashLookup
  # class to handle all the fields for easier lookup later.
  class HashLookup
    attr_accessor :db_hash, :jtr_hash, :username, :id

    def initialize(db_hash, jtr_hash, username, id)
      @db_hash = db_hash
      @jtr_hash = jtr_hash
      @username = username
      @id = id
    end
  end

  def show_run_command(cracker_instance)
    return unless datastore['ShowCommand']

    cmd = cracker_instance.show_command
    print_status("   Cracking Command: #{cmd.join(' ')}")
  end

  def run
    cracker = new_password_cracker(action.name)

    lookups = []

    # create one massive hash file with all the hashes
    hashlist = Rex::Quickfile.new('hashes_tmp')
    framework.db.creds(workspace: myworkspace).each do |core|
      next if core.private.type == 'Metasploit::Credential::Password'

      jtr_hash = Metasploit::Framework::PasswordCracker::JtR::Formatter.hash_to_jtr(core)
      hashlist.puts jtr_hash
      lookups << HashLookup.new(core.private.data, jtr_hash, core.public, core.id)
    end
    hashlist.close
    cracker.hash_path = hashlist.path
    print_status "Hashes Written out to #{hashlist.path}"
    cleanup_files = [cracker.hash_path]

    # cycle through all hash types we dump asking jtr to show us
    # cracked passwords.  The advantage to this vs just comparing
    # john.pot to the hashes directly is we use jtr to recombine
    # lanman, and other assorted nuances
    [
      'bcrypt', 'bsdicrypt', 'descrypt', 'lm',
      'mscash', 'mscash2', 'netntlm', 'netntlmv2',
      'md5crypt', 'mysql', 'mysql-sha1', 'mssql', 'mssql05', 'mssql12',
      'oracle', 'oracle11', 'oracle12c', 'dynamic_1506', # oracles
      'dynamic_1034', # postgres
      # 'android-sha1', 'android-samsung-sha1', 'android-md5', # mobile is done with hashcat, so skip these
      'PBKDF2-HMAC-SHA1', 'phpass', 'mediawiki', 'pbkdf2-sha256', # webapps
      'xsha', 'xsha512', 'PBKDF2-HMAC-SHA512', # osx
      'nt', # nt needs to be 2nd to last because it can hit on android hashes
      'crypt' # crypt NEEDS TO BE LAST so it doesn't accidentally read in other compatible hashes
    ].each do |format|
      print_status("Checking #{format} hashes against pot file")
      cracker.format = format
      show_run_command(cracker)
      cracker.each_cracked_password.each do |password_line|
        password_line.chomp!
        next if password_line.blank? || password_line.nil?

        fields = password_line.split(':')
        core_id = nil
        case format
        when 'descrypt'
          next unless fields.count >= 3

          username = fields.shift
          core_id = fields.pop
          4.times { fields.pop } # Get rid of extra :
        when 'netntlm', 'netntlmv2'
          next unless fields.count >= 7

          username = fields.shift
          core_id = fields.pop
          9.times { fields.pop }
        when 'md5crypt', 'bsdicrypt', 'crypt', 'bcrypt', 'xsha', 'xsha512'
          next unless fields.count >= 7

          username = fields.shift
          core_id = fields.pop
          4.times { fields.pop }
        when 'PBKDF2-HMAC-SHA512'
          next unless fields.count >= 2

          username = fields.shift
          core_id = fields.pop
        when 'mssql', 'mssql05', 'mssql12', 'mysql', 'mysql-sha1',
             'oracle', 'dynamic_1506', 'oracle11', 'oracle12c',
             'PBKDF2-HMAC-SHA1', 'phpass', 'mediawiki', 'pbkdf2-sha256',
             'mscash', 'mscash2'
          next unless fields.count >= 3

          username = fields.shift
          core_id = fields.pop
        when 'dynamic_1034' # postgres
          next unless fields.count >= 2

          username = fields.shift
          fields.join(':')
          # unfortunately to match up all the fields we need to pull the hash
          # field as well, and it is only available in the pot file.
          pot = cracker.pot || cracker.john_pot_file

          File.open(pot, 'rb').each do |line|
            next unless line.start_with?('$dynamic_1034$') # postgres format

            lookups.each do |l|
              pot_hash = line.split(':')[0]
              raw_pot_hash = pot_hash.split('$')[2]
              next unless l.username.to_s == username &&
                          l.jtr_hash == "#{username}:$dynamic_1034$#{raw_pot_hash}" &&
                          l.db_hash == raw_pot_hash

              core_id = l.id
              break
            end
          end
        when 'lm', 'nt'
          next unless fields.count >= 7

          username = fields.shift
          core_id = fields.pop
          2.times { fields.pop }
          # get the NT and LM hashes
          nt_hash = fields.pop
          fields.pop
          core_id = fields.pop
          password = fields.join(':')
          if format == 'lm'
            if password.blank?
              if nt_hash == Metasploit::Credential::NTLMHash::BLANK_NT_HASH
                password = ''
              else
                next
              end
            end
            password = john_lm_upper_to_ntlm(password, nt_hash)
            next if password.nil?
          end
          fields = password.split(':') # for consistency on the following join out of the case
        end
        next if core_id.nil?

        password = fields.join(':')
        print_good "#{username}:#{password}"
        # android hashes will also crack here, but the output fields are in a different order
        # check if core_id is an int or not, for android hashes it wont convert
        core_id_int = begin
          Integer(core_id)
        rescue StandardError
          nil
        end
        next if core_id_int.nil?

        create_cracked_credential(username: username, password: password, core_id: core_id)
      end
    end
    if datastore['DeleteTempFiles']
      cleanup_files.each do |f|
        File.delete(f)
      end
    end
  end
end
