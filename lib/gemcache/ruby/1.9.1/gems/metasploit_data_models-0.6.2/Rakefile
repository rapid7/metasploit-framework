#!/usr/bin/env rake
begin
  require 'bundler/setup'
rescue LoadError
  puts 'You must `gem install bundler` and `bundle install` to run rake tasks'
end

print_without = false
APP_RAKEFILE = File.expand_path('../spec/dummy/Rakefile', __FILE__)

begin
  load 'rails/tasks/engine.rake'
rescue LoadError
  puts "railties not in bundle, so can't load engine tasks."
  print_without = true
end

Bundler::GemHelper.install_tasks

#
# load rake files like a normal rails app
# @see http://viget.com/extend/rails-engine-testing-with-rspec-capybara-and-factorygirl
#

pathname = Pathname.new(__FILE__)
root = pathname.parent
rakefile_glob = root.join('lib', 'tasks', '**', '*.rake').to_path

Dir.glob(rakefile_glob) do |rakefile|
  load rakefile
end

begin
  require 'rspec/core'
rescue LoadError
  puts "rspec not in bundle, so can't set up spec tasks.  " \
       "To run specs ensure to install the development and test groups."
  print_without = true
else
  require 'rspec/core/rake_task'

  # Depend on app:db:test:prepare so that test database is recreated just like in a full rails app
  # @see http://viget.com/extend/rails-engine-testing-with-rspec-capybara-and-factorygirl
  RSpec::Core::RakeTask.new(:spec => 'app:db:test:prepare')

  task :default => :spec
end

if print_without
  puts "Bundle currently installed '--without #{Bundler.settings.without.join(' ')}'."
  puts "To clear the without option do `bundle install --without ''` (the --without flag with an empty string) or " \
       "`rm -rf .bundle` to remove the .bundle/config manually and then `bundle install`"
end
