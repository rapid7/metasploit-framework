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

require 'digest'
require 'metasploit/framework/version'
require 'msf/base/config'

# Invalidate and delete the bootsnap cache if required. For instance if the metasploit-framework version has changed.
#
# @param [Hash] bootsnap_config See https://github.com/Shopify/bootsnap/blob/95e8d170aea99a831fd484ce09ad2f195644e740/lib/bootsnap.rb#L38
# @return [void]
def invalidate_bootsnap_cache!(bootsnap_config)
  expected_cache_metadata = {
    'metasploit_framework_version' => Metasploit::Framework::Version::VERSION,
    'ruby_description' => RUBY_DESCRIPTION,
    'bundler_lockfile_hash' => Digest::MD5.hexdigest(Bundler.read_file(Bundler.default_lockfile)),
    'bootsnap_config' => {
      'load_path_cache' => bootsnap_config[:load_path_cache],
      'compile_cache_iseq' => bootsnap_config[:compile_cache_iseq],
      'compile_cache_yaml' => bootsnap_config[:compile_cache_yaml],
    }
  }

  cache_metadata_path = File.join(bootsnap_config[:cache_dir], "metadata.yaml")
  if File.exist?(cache_metadata_path)
    cache_metadata = YAML.safe_load(File.binread(cache_metadata_path))
    if cache_metadata != expected_cache_metadata
      FileUtils.rm_rf(bootsnap_config[:cache_dir], secure: true)
    end
  end

  FileUtils.mkdir_p(bootsnap_config[:cache_dir])
  File.binwrite(cache_metadata_path, expected_cache_metadata.to_yaml)

  nil
end

# Attempt to use bootsnap caching for improved startup time
begin
  require 'bootsnap'
  env = ENV['RAILS_ENV'] || ENV['RACK_ENV'] || ENV['ENV']
  development_mode = ['', nil, 'development'].include?(env)

  cache_dir = ::File.join(Msf::Config.config_directory, "bootsnap_cache")
  bootsnap_config = {
    cache_dir: cache_dir,
    ignore_directories: [],
    development_mode: development_mode,
    load_path_cache: true, # Optimize the LOAD_PATH with a cache
    compile_cache_iseq: false, # Don't compile Ruby code into ISeq cache, breaks coverage reporting.
    compile_cache_yaml: false, # Don't compile YAML into a cache
    readonly: false, # Update caches - https://github.com/Shopify/bootsnap/commit/b51397f96c33aa421fd5c29484fb9574df9eb451
  }
  invalidate_bootsnap_cache!(bootsnap_config)
  Bootsnap.setup(**bootsnap_config)
rescue
  $stderr.puts 'Warning: Failed bootsnap cache setup'
  begin
    FileUtils.rm_rf(cache_dir, secure: true)
  rescue
    $stderr.puts 'Warning: Failed deleting bootsnap cache'
  end
end
