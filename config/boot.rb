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

# Remove bigdecimal warning - start
# https://github.com/ruby/bigdecimal/pull/115
# https://github.com/rapid7/metasploit-framework/pull/11184#issuecomment-461971266
# TODO: remove when upgrading from rails 4.x
require 'bigdecimal'

def BigDecimal.new(*args, **kwargs)
  return BigDecimal(*args) if kwargs.empty?
  BigDecimal(*args, **kwargs)
end
# Remove bigdecimal warning - end

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
