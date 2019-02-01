##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/jtr'

class MetasploitModule < Msf::Auxiliary
  #include Msf::Auxiliary::Report
  include Msf::Auxiliary::JohnTheRipper

  def initialize
    super(
      'Name'            => 'Apply Pot File To Hashes',
      'Description'     => %Q{
          This module uses a John the Ripper or Hashcat .pot file to crack any password
        hashes in the creds database instantly.  JtR's --show functionality is used to 
        help combine all the passwords into an easy to use format.
      },
      'Author'          => ['h00die'],
      'License'         => MSF_LICENSE
    )
  end

  def run
    cracker = new_john_cracker

    lookups = []

    # create one massive hash file with all the hashes 
    hashlist = Rex::Quickfile.new("hashes_tmp")
    framework.db.creds(workspace: myworkspace).each do |core|
      next if core.private.type == 'Metasploit::Credential::Password'
      jtr_hash = hash_to_jtr(core)
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
    ['lm', 'nt', 'dynamic_1034', 'oracle11', 'oracle12c', 'dynamic_1506',
     'oracle', 'md5crypt', 'descrypt', 'bcrypt', 'crypt', 'mysql', 'mysql-sha1',
     'mssql', 'mssql05', 'mssql12', 'bsdicrypt'].each do |format|
 
      print_status("Checking #{format} hashes against pot file")
      cracker.format = format
      cracker.each_cracked_password do |password_line|
        password_line.chomp!
        next if password_line.blank? || password_line.nil?
        fields = password_line.split(":")
        core_id = nil
        case format
        when 'descrypt'
          next unless fields.count >=3
          username = fields.shift
          core_id  = fields.pop
          4.times { fields.pop } # Get rid of extra :
        when 'md5crypt', 'descrypt', 'bsdicrypt', 'crypt', 'bcrypt'
          next unless fields.count >=7
          username = fields.shift
          core_id  = fields.pop
          4.times { fields.pop }
        when 'mssql', 'mssql05', 'mssql12', 'mysql', 'mysql-sha1',
             'oracle', 'dynamic_1506', 'oracle11', 'oracle12c'
          next unless fields.count >=3
          username = fields.shift
          core_id  = fields.pop
        when 'dynamic_1034' #postgres
          next unless fields.count >=2
          username = fields.shift
        when 'lm', 'nt'
          next unless fields.count >=7
          username = fields.shift
          core_id = fields.pop
          2.times{ fields.pop }
          # get the NT and LM hashes
          nt_hash = fields.pop
          lm_hash = fields.pop
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
          fields = password.split(':') #for consistency on the following join out of the case
        end
        password = fields.join(':')        
        print_good "#{username}:#{password}"
        unless core_id.nil?
          create_cracked_credential( username: username, password: password, core_id: core_id)
        end
      end
    end
    cleanup_files.each do |f|
      #File.delete(f)
    end
  end
end
