##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Module::Deprecated

  deprecated(Date.new(2019, 10, 30), 'auxiliary/analyze/crack_linux')

  def initialize
    super(
      'Name'            => 'John the Ripper Linux Password Cracker',
      'Description'     => %Q{
          This module uses John the Ripper to identify weak passwords that have been
        acquired from unshadowed passwd files from Unix systems. The module will only crack
        MD5, BSDi and DES implementations by default. Set Crypt to true to also try to crack
        Blowfish and SHA(256/512). Warning: This is much slower.
      },
      'Author'          =>
        [
          'theLightCosine',
          'hdm'
        ] ,
      'License'         => MSF_LICENSE  # JtR itself is GPLv2, but this wrapper is MSF (BSD)
    )

    register_options(
      [
        OptBool.new('Crypt',[false, 'Try crypt() format hashes(Very Slow)', false])
      ]
    )

  end

  def run
    fail_with(Failure::BadConfig, 'This module has been enhanced and move to: auxiliary/analyze/crack_linux')
  end
end
