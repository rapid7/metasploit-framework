#!/usr/bin/env rake
require File.expand_path('../config/application', __FILE__)
require 'metasploit/framework/require'
require 'metasploit/framework/spec/untested_payloads'

# @note must be before `Metasploit::Framework::Application.load_tasks`
#
# define db rake tasks from activerecord if activerecord is in the bundle.  activerecord could be not in the bundle if
# the user installs with `bundle install --without db`
Metasploit::Framework::Require.optionally_active_record_railtie

begin
  require 'rspec/core'
  require 'rspec-rerun/tasks'
rescue LoadError
  puts "rspec not in bundle, so can't set up spec tasks.  " \
       "To run specs ensure to install the development and test groups."
  puts "Bundle currently installed '--without #{Bundler.settings.without.join(' ')}'."
  puts "To clear the without option do `bundle install --without ''` (the --without flag with an empty string) or " \
       "`rm -rf .bundle` to remove the .bundle/config manually and then `bundle install`"
else
  require 'rspec/core/rake_task'
  RSpec::Core::RakeTask.new(spec: 'db:test:prepare')
end

Metasploit::Framework::Application.load_tasks
Metasploit::Framework::Spec::Constants.define_task
Metasploit::Framework::Spec::Threads::Suite.define_task
Metasploit::Framework::Spec::UntestedPayloads.define_task
