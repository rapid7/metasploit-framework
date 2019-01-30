##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##



## redo all this and let john --show do the work.
## also create a hash file with everything in it to test.



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
    register_options([
      OptPath.new('POT', [true, '.pot file to apply to password hashes', '/'])
    ])

  end

  def run
    cracker = new_john_cracker

    # this is our lookup table for translating hashes to jtr style
    # to what is in the database
    hashes = []

    class HashLookup
      def initialize(db_hash, jtr_hash, username, id)
        @db_hash = db_hash
        @jtr_hash = jtr_hash
        @username = username
        @id = id
      end
    end

    # create a hash file with all the hashes
    framework.db.creds(workspace: myworkspace).each do |core|
      next if type == 'Metasploit::Credential::Password'
        user = core.public.username
        case core.private.jtr_type
        when 'oracle12c'
          if core.private.data =~ /T:([\dA-F]{160})/
            jtr_hash = "$oracle12c$#{$1.downcase}"
          end
        when 'oracle11'
          if core.private.data =~ /S:([\dA-F]{60})/
            jtr_hash_string = $1
          end
        when 'dynamic_1506'
          if core.private.data =~ /H:([\dA-F]{32})/
            user = user.upcase
            jtr_hash = "$dynamic_1506$#{$1}"
          end
        when /postgres|raw-md5/
          jtr_hash = core.private.data
          jtr_hash.gsub!(/^md5/, '')
          jtr_hash = "#{user}:$dynamic_1034$#{jtr_hash}"
        else
          #des, md5, sha1, crypt, bf, bsdi
          #mssql, mssql05, mssql12
          #mysql, mysql-sha1
        end
        hash = HashLooup.new(core.private.data, jtr_hash, user, core.id)
    end

    # Load the pot file
    unless ::File.file?(datastore['POT'])
      fail_with Failure::NotFound, ".pot file #{datastore['POT']} not found"
    end
    f = ::File.open(datastore['POT'], 'rb')
    pot = f.read(f.stat.size)
    f.close

    framework.db.creds(workspace: myworkspace).each do |core|
      next if type == 'Metasploit::Credential::Password'
      pot.each_line do |p|
        p = p.split(":")
        pot_hash = p.shift
        password = p.join(":")
        username = core.public.username
        db_hash = core.private.data
        # we need to do some manipulation here to make sure everything matches up correctly
        next unless db_hash == pot_hash
        print_good("Found #{username}:#{password}")
        create_cracked_credential( username: username, password: password, core_id: core.id)
      end
    end
  end
end
