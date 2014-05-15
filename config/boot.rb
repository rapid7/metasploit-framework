require 'pathname'
require 'rubygems'

bundle_gemfile = ENV['BUNDLE_GEMFILE']

config_pathname = Pathname.new(__FILE__).expand_path.parent
root = config_pathname.parent

if bundle_gemfile
  bundle_gemfile = Pathname.new(bundle_gemfile)
else
  bundle_gemfile = root.join('Gemfile')
end

if bundle_gemfile.exist?
  ENV['BUNDLE_GEMFILE'] = bundle_gemfile.to_path

  begin
    require 'bundler'
  rescue LoadError
    $stderr.puts "[*] Metasploit requires the Bundler gem to be installed"
    $stderr.puts "    $ gem install bundler"
    exit(0)
  end
end

Bundler.setup

lib_path = root.join('lib').to_path

unless $LOAD_PATH.include? lib_path
  $LOAD_PATH.unshift lib_path
end
