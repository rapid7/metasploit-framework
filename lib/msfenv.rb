#
# Use bundler to load dependencies
#

GEMFILE_EXTENSIONS = [
  '.local',
  ''
]

unless ENV['BUNDLE_GEMFILE']
  require 'pathname'

  msfenv_real_pathname = Pathname.new(__FILE__).realpath
  root = msfenv_real_pathname.parent.parent

  GEMFILE_EXTENSIONS.each do |extension|
    extension_pathname = root.join("Gemfile#{extension}")

    if extension_pathname.readable?
      ENV['BUNDLE_GEMFILE'] ||= extension_pathname.to_path
      break
    end
  end
end

begin
  require 'bundler/setup'
rescue ::LoadError
  $stderr.puts "[*] Metasploit requires the Bundler gem to be installed"
  $stderr.puts "    $ gem install bundler"
  exit(0)
end
