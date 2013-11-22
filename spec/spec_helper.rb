# -*- coding:binary -*-

# Test Ruby for CVE-2013-4164
# See https://www.ruby-lang.org/en/news/2013/11/22/heap-overflow-in-floating-point-parsing-cve-2013-4164/
$cve_2013_4164_tested ||= false
unless $cve_2013_4164_tested
  $stdout.puts "\n[*] Testing for CVE-2013-4164. If this crashes, update your Ruby version.\n"
  10.times { ("1."+"1"*300000).to_f }
  $cve_2013_4164_tested = true
  $stdout.puts "[*] Success, Ruby survived the segfaulting test."
end

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
require 'rspec/core'

# Requires supporting ruby files with custom matchers and macros, etc,
# in spec/support/ and its subdirectories.
support_glob = root_pathname.join('spec', 'support', '**', '*.rb')

Dir.glob(support_glob) do |path|
  require path
end

RSpec.configure do |config|
  config.mock_with :rspec

  # Can't use factory_girl_rails since not using rails, so emulate
  # factory_girl.set_factory_paths initializer and after_initialize for
  # FactoryGirl::Railtie
  config.before(:suite) do
    # Need to load Mdm models first so factories can use them
    MetasploitDataModels.require_models

    FactoryGirl.definition_file_paths = [
        MetasploitDataModels.root.join('spec', 'factories'),
        # Have metasploit-framework's definition file path last so it can
        # modify gem factories.
        Metasploit::Framework.root.join('spec', 'factories')
    ]

    FactoryGirl.find_definitions
  end
end

