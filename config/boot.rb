require 'pathname'
require 'rubygems'
require 'scanf'

GEMFILE_EXTENSIONS = [
    '.local',
    ''
]

msfenv_real_pathname = Pathname.new(__FILE__).realpath
root = msfenv_real_pathname.parent.parent

unless ENV['BUNDLE_GEMFILE']
  require 'pathname'

  GEMFILE_EXTENSIONS.each do |extension|
    extension_pathname = root.join("Gemfile#{extension}")

    if extension_pathname.readable?
      ENV['BUNDLE_GEMFILE'] = extension_pathname.to_path
      break
    end
  end
end

begin
  require 'bundler/setup'
rescue LoadError => e
  msg = e.to_s
  ver = msg.scanf("You have already activated bundler %d.%d.%d, but your Gemfile requires bundler %d.%d.%d.")
  if ver.length == 6
    installed_ver = "#{ver[0]}.#{ver[1]}.#{ver[2]}"
    wanted_ver = "#{ver[3]}.#{ver[4]}.#{ver[5]}"
    $stderr.puts "[*] Bundler #{installed_ver} and #{wanted_ver} are conflicting with Ruby #{RUBY_VERSION}. Please uninstall:"
    $stderr.puts "    $ gem uninstall bundler -v #{ver[0]}.#{ver[1]}.#{ver[2]}"
  else
    $stderr.puts "[*] Bundler failed to load: '#{e}'"
    $stderr.puts
    $stderr.puts "[*] Metasploit requires the Bundler gem to be installed. You may need to run:"
    $stderr.puts "    $ gem install bundler"
  end
  exit(1)
end

lib_path = root.join('lib').to_path

unless $LOAD_PATH.include? lib_path
  $LOAD_PATH.unshift lib_path
end
