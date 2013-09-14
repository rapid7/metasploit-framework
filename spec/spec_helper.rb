# -*- coding:binary -*-
require 'rubygems'
require 'bundler'
Bundler.require(:default, :test, :db)

FILE_FIXTURES_PATH = File.expand_path(File.dirname(__FILE__)) + "/file_fixtures/"

# add project lib directory to load path
spec_pathname = Pathname.new(__FILE__).dirname
root_pathname = spec_pathname.join('..').expand_path
lib_pathname = root_pathname.join('lib')
$LOAD_PATH.unshift(lib_pathname.to_s)

# must be first require and started before any other requires so that it can measure coverage of all following required
# code.  It is after the rubygems and bundler only because Bundler.setup supplies the LOAD_PATH to simplecov.
require 'simplecov'

# now that simplecov is loaded, load everything else
require 'metasploit/framework'
require 'rspec/core'

# Requires supporting ruby files with custom matchers and macros, etc,
# in spec/support/ and its subdirectories.

# In order that allows later paths to modify early path's factories
rooteds = [
		Metasploit::Model,
		MetasploitDataModels,
		Metasploit::Framework
]

support_globs = rooteds.collect { |rooted|
	rooted.root.join('spec', 'support', '**', '*.rb')
}

support_globs.each do |support_glob|
	Dir.glob(support_glob) do |path|
		require path
	end
end

RSpec.configure do |config|
  config.mock_with :rspec

  # Can't use factory_girl_rails since not using rails, so emulate
  # factory_girl.set_factory_paths initializer and after_initialize for
  # FactoryGirl::Railtie
  config.before(:suite) do
	  # Need to load Mdm models first so factories can use them
	  MetasploitDataModels.require_models

		Metasploit::Model::Spec.temporary_pathname = Metasploit::Framework.root.join('spec', 'tmp')
		# Clean up any left over files from a previously aborted suite
		Metasploit::Model::Spec.remove_temporary_pathname

		FactoryGirl.definition_file_paths = rooteds.collect { |rooted|
			rooted.root.join('spec', 'factories')
		}

		FactoryGirl.find_definitions
  end

  config.before(:each) do
    if defined? Msf::Modules
      inherit = false
      constants = Msf::Modules.constants(inherit)

      constants.each do |constant|
        $stderr.puts "#{constant} not removed from Msf::Modules."
      end

      unless constants.empty?
        $stderr.puts "Use `include_context 'Msf::Modules Cleaner'` to clean up Msf::Modules constants from specs"
      end
    end
  end

	config.after(:each) do
		Metasploit::Model::Spec.remove_temporary_pathname
  end

  config.after(:suite) do
    if defined? Msf::Modules
      inherit = false
      constants = Msf::Modules.constants(inherit)

      constants.each do |constant|
        $stderr.puts "#{constant} not removed from Msf::Modules."
      end

      unless constants.empty?
        $stderr.puts "Use `include_context 'Msf::Modules Cleaner'` to clean up Msf::Modules constants from specs"
      end
    end
  end
end

