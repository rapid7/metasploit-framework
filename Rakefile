#!/usr/bin/env rake
require File.expand_path('../config/application', __FILE__)
require 'metasploit/framework/require'

# @note must be before `Metasploit::Framework::Application.load_tasks`
#
# define db rake tasks from activerecord if activerecord is in the bundle.  activerecord could be not in the bundle if
# the user installs with `bundle install --without db`
Metasploit::Framework::Require.optionally_active_record_railtie

Metasploit::Framework::Application.load_tasks


begin
  require 'cucumber'
  require 'cucumber/rake/task'
  Cucumber::Rake::Task.new(:features) do |t|
    t.cucumber_opts = 'features --format pretty'
  end
rescue LoadError
  puts "cucumber not in bundle, so can't set up feature tasks.  " \
       "To run features ensure to install the development and test groups."
end