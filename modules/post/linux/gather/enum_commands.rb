##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::System

  def initialize
    super(
      'Name' => 'Gather Available Shell Commands',
      'Description' => %q{
        This module will check which shell commands are available on a system."
      },
      'Author' => 'Alberto Rafael Rodriguez Iglesias <albertocysec[at]gmail.com>',
      'License' => MSF_LICENSE,
      'Platform' => ['linux', 'unix'],
      'SessionTypes' => ['shell', 'meterpreter'],
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'Reliability' => [],
        'SideEffects' => []
      }
    )
    register_options([
      OptString.new('DIR', [false, 'Optional directory name to list (in addition to default system PATH and common paths)', ''])
    ])
  end

  def run
    path = get_path

    print_warning('System PATH is empty!') if path.blank?

    paths = []
    path.split(':').each do |p|
      paths << p.chomp('/')
    end

    common_dirs = [
      '/root/local/bin',
      '/usr/local/sbin',
      '/usr/local/bin',
      '/usr/sbin',
      '/usr/bin',
      '/sbin',
      '/bin',
      '/usr/local/go/bin'
    ]

    common_dirs << datastore['DIR'] unless datastore['DIR'].blank?

    common_dirs.each do |p|
      paths << p.chomp('/')
    end

    binaries = []

    paths.sort.uniq.each do |p|
      next unless directory?(p)

      files = dir(p)

      next if files.blank?

      files.each do |f|
        binaries << "#{p}/#{f.strip}"
      end
    end

    # BusyBox commands
    busybox_path = nil
    if command_exists?('busybox')
      busybox_path = 'busybox'
    elsif command_exists?('/bin/busybox')
      busybox_path = '/bin/busybox'
    end

    unless busybox_path.blank?
      busybox_cmds = cmd_exec("#{busybox_path} --list")
      busybox_cmds.each_line do |cmd|
        binaries << "busybox #{cmd.strip}"
      end
    end

    # A recursive `ls /` or `find / -executable -type f`
    # could be added to find extra binaries.

    print_good("Found #{binaries.sort.uniq.length} executable binaries/commands")

    binaries.uniq.sort.each do |bin|
      print_line(bin)
    end
  end
end
