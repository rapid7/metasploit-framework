##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Module::Deprecated

  deprecated(Date.new(2019, 12, 31))

  def initialize
    super(
      'Name'        => 'John the Ripper Windows Password Cracker (Fast Mode)',
      'Description' => %Q{
          This module uses John the Ripper to identify weak passwords that have been
        acquired as hashed files (loot) or raw LANMAN/NTLM hashes (hashdump). The goal
        of this module is to find trivial passwords in a short amount of time. To
        crack complex passwords or use large wordlists, John the Ripper should be
        used outside of Metasploit. This initial version just handles LM/NTLM credentials
        from hashdump and uses the standard wordlist and rules.
      },
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE  # JtR itself is GPLv2, but this wrapper is MSF (BSD)
    )
  end

  def run
    fail_with(Failure::BadConfig, 'This module has been enhanced and move to: auxiliary/analyze/crack_windows')
  end
end
