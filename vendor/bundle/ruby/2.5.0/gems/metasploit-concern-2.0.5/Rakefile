#!/usr/bin/env rake
begin
  require 'bundler/setup'
rescue LoadError
  puts 'You must `gem install bundler` and `bundle install` to run rake tasks'
end

print_without = false
APP_RAKEFILE = File.expand_path("../spec/dummy/Rakefile", __FILE__)

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
  require 'cucumber'
  require 'cucumber/rake/task'
rescue LoadError
  puts "cucumber not in bundle, so can't set up features task.  " \
       "To run features ensure to install the development and test groups."
  print_without = true
else
  Cucumber::Rake::Task.new(:cucumber) do |t|
    t.cucumber_opts = 'features --format pretty'
  end
end

begin
  require 'rspec/core'
rescue LoadError
  puts "rspec not in bundle, so can't set up spec tasks.  " \
       "To run specs ensure to install the development and test groups."
  print_without = true
else
  require 'rspec/core/rake_task'

  # @see http://viget.com/extend/rails-engine-testing-with-rspec-capybara-and-factorygirl
  RSpec::Core::RakeTask.new(:spec)

  task :default => :spec
end

# Use find_all_by_name instead of find_by_name as find_all_by_name will return pre-release versions
gem_specification = Gem::Specification.find_all_by_name('metasploit-yard').first

if gem_specification
  Dir[File.join(gem_specification.gem_dir, 'lib', 'tasks', '**', '*.rake')].each do |rake|
    load rake
  end
else
  puts "metasploit-yard not in bundle, so can't setup yard tasks. " \
       "To run yard ensure to install the development group."
  print_without = true
end

if print_without
  puts "Bundle currently installed '--without #{Bundler.settings.without.join(' ')}'."
  puts "To clear the without option do `bundle install --without ''` (the --without flag with an empty string) or " \
       "`rm -rf .bundle` to remove the .bundle/config manually and then `bundle install`"
end