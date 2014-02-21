#
# Use bundler to load dependencies
#

gemfile_base = ::File.expand_path(::File.join(::File.dirname(__FILE__), ".."))
if File.readable?(::File.join(gemfile_base,"Gemfile.local"))
  ENV['BUNDLE_GEMFILE'] ||= ::File.join(gemfile_base, "Gemfile.local")
else
  ENV['BUNDLE_GEMFILE'] ||= ::File.join(gemfile_base, "Gemfile")
end

begin
  require 'bundler/setup'
rescue ::LoadError
  $stderr.puts "[*] Metasploit requires the Bundler gem to be installed"
  $stderr.puts "    $ gem install bundler"
  exit(0)
end
