##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Linux::System

  def initialize
    super(
      'Name'         => 'Testing commands needed in a function',
      'Description'  => %q{
        This module will be applied on a session connected to a shell. It will check which commands are available in the system.
      },
      'Author'       => 'Alberto Rafael Rodriguez Iglesias <albertocysec[at]gmail.com>',
      'License'      => MSF_LICENSE,
      'Platform'     => ['linux'],
      'SessionTypes' => ['shell', 'meterpreter']
    )
    register_options(
      [
        OptString.new('DIR', [false, 'Optional directory name to list, default current session path',''])
      ])
  end

  DIRS = [
    "/root/local/bin/",
    "/usr/local/sbin/",
    "/usr/local/bin/",
    "/usr/sbin/",
    "/usr/bin/",
    "/sbin/",
    "/bin/",
    "/usr/local/go/bin/"
  ]

  def run
    dir = datastore['DIR']
    binaries = []

    # Explore the $PATH directories
    path_dirs = cmd_exec("echo $PATH").split(':')
    path_dirs.each do |d|
      elems = dir(d)
      path = pwd()
      elems.each do |elem|
        binaries.insert(-1, "#{d}/#{elem}")
      end
    end

    # Explore common directories with binaries:
    DIRS.each do |d|
#      if dir_exist?(d)
        elems = dir(d)
        path = pwd()
        elems.each do |elem|
          binaries.insert(-1, "#{d}#{elem}")
        end
    end

    # Busybox commands
    if command_exists?("busybox")
      output = cmd_exec("busybox")
      busybox_cmds = output.split(':')[-1].chomp.split(',')
      busybox_cmds.each do |cmd|
        binaries.insert(-1, "busybox #{cmd}")
        print_good("busybox #{cmd}")
      end
    elsif command_exists?("/bin/busybox")
      output = cmd_exec("(bin/busybox")
    end

# A recursive ls through the whole system could be added to find extra binaries

    binaries.uniq
    binaries.sort

    print_good("The following binaries/commands are available")
    binaries.each do |bin|
      print_line("#{bin}")
    end

  end
end
