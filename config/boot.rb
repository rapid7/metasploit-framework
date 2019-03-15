require 'pathname'
require 'rubygems'

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
  $stderr.puts "[*] Bundler failed to load and returned this error:"
  $stderr.puts
  $stderr.puts "   '#{e}'"
  $stderr.puts
  $stderr.puts "[*] You may need to uninstall or upgrade bundler"
  exit(1)
end

lib_path = root.join('lib').to_path

unless $LOAD_PATH.include? lib_path
  $LOAD_PATH.unshift lib_path
end
