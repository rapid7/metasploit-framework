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
        'Name' => 'Windows Gather PowerShell Environment Setting Enumeration',
        'Description' => %q{ This module will enumerate Microsoft PowerShell settings. },
        'License' => MSF_LICENSE,
        'Author' => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
        'Platform' => [ 'win' ],
        'References' => [
          ['URL', 'https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies'],
          ['URL', 'https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_profiles'],
        ],
        'SessionTypes' => %w[meterpreter shell powershell],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        },
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              core_channel_eof
              core_channel_open
              core_channel_read
              core_channel_write
              stdapi_sys_config_getenv
              stdapi_sys_config_getuid
            ]
          }
        }
      )
    )
  end

  def enum_users
    users = []

    system_drive = get_env('SystemDrive').to_s.strip

    path4users = ''
    if directory?("#{system_drive}\\Users")
      path4users = "#{system_drive}\\Users\\"
      profilepath = '\\Documents\\WindowsPowerShell\\'
    elsif directory?("#{system_drive}\\Documents and Settings")
      path4users = "#{system_drive}\\Documents and Settings\\"
      profilepath = '\\My Documents\\WindowsPowerShell\\'
    else
      print_error('Could not find user profile directories')
      return []
    end

    if is_system? || is_admin?
      print_status('Running with elevated privileges. Extracting user list ...')
      paths = begin
        dir(path4users)
      rescue StandardError
        []
      end

      ignored = [
        '.',
        '..',
        'All Users',
        'Default',
        'Default User',
        'Public',
        'desktop.ini',
        'LocalService',
        'NetworkService'
      ]
      paths.reject { |p| ignored.include?(p) }.each do |u|
        users << {
          'username' => u,
          'userappdata' => path4users + u + profilepath
        }
      end
    else
      u = get_env('USERNAME')
      users << {
        'username' => u,
        'userappdata' => path4users + u + profilepath
      }
    end

    users
  end

  def enum_powershell_modules
    powershell_module_path = get_env('PSModulePath')
    return [] unless powershell_module_path

    paths = powershell_module_path.split(';')
    print_status('PowerShell Modules paths:')
    modules = []
    paths.each do |p|
      print_status("\t#{p}")

      path_contents = begin
        dir(p)
      rescue StandardError
        []
      end
      path_contents.reject { |m| ['.', '..'].include?(m) }.each do |m|
        modules << m
      end
    end

    modules
  end

  def enum_powershell
    unless registry_enumkeys('HKLM\\SOFTWARE\\Microsoft').include?('PowerShell')
      print_error('PowerShell is not installed on this system.')
      return
    end

    print_status('PowerShell is installed on this system.')

    powershell_version = registry_getvaldata('HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\PowerShellEngine', 'PowerShellVersion')
    print_status("Version: #{powershell_version}")

    powershell_policy = begin
      registry_getvaldata('HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell', 'ExecutionPolicy')
    rescue StandardError
      'Restricted'
    end
    print_status("Execution Policy: #{powershell_policy}")

    powershell_path = registry_getvaldata('HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell', 'Path')
    print_status("Path: #{powershell_path}")

    if registry_enumkeys('HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1').include?('PowerShellSnapIns')
      print_status('PowerShell Snap-Ins:')
      registry_enumkeys('HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\PowerShellSnapIns').each do |si|
        print_status("\tSnap-In: #{si}")
        registry_enumvals("HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\PowerShellSnapIns\\#{si}").each do |v|
          print_status("\t\t#{v}: #{registry_getvaldata("HKLM\\SOFTWARE\\Microsoft\\PowerShell\\1\\PowerShellSnapIns\\#{si}", v)}")
        end
      end
    else
      print_status('No PowerShell Snap-Ins are installed')
    end

    modules = enum_powershell_modules
    if modules && !modules.empty?
      print_status('PowerShell Modules:')
      modules.each do |m|
        print_status("\t#{m}")
      end
    else
      print_status('No PowerShell Modules are installed')
    end

    profile_file_names = [
      'profile.ps1',
      'Microsoft.PowerShell_profile.ps1',
      'Microsoft.VSCode_profile.ps1',
    ]

    print_status('Checking if users have PowerShell profiles')
    enum_users.each do |u|
      print_status("Checking #{u['username']}")

      app_data_contents = begin
        dir(u['userappdata'])
      rescue StandardError
        []
      end
      app_data_contents.map!(&:downcase)

      profile_file_names.each do |profile_file|
        next unless app_data_contents.include?(profile_file.downcase)

        fname = "#{u['userappdata']}#{profile_file}"

        ps_profile = begin
          read_file(fname)
        rescue StandardError
          nil
        end
        next unless ps_profile

        print_status("Found PowerShell profile '#{fname}' for #{u['username']}:")
        print_line(ps_profile.to_s)
      end
    end
  end

  def run
    hostname = sysinfo.nil? ? cmd_exec('hostname') : sysinfo['Computer']
    print_status("Running module against #{hostname} (#{session.session_host})")
    enum_powershell
  end
end
