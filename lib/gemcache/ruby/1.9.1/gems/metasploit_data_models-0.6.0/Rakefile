#!/usr/bin/env rake
begin
  require 'bundler/setup'
rescue LoadError
  puts 'You must `gem install bundler` and `bundle install` to run rake tasks'
end

APP_RAKEFILE = File.expand_path('../spec/dummy/Rakefile', __FILE__)
load 'rails/tasks/engine.rake'

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

require 'rspec/core'
require 'rspec/core/rake_task'

# Depend on app:db:test:prepare so that test database is recreated just like in a full rails app
# @see http://viget.com/extend/rails-engine-testing-with-rspec-capybara-and-factorygirl
RSpec::Core::RakeTask.new(:spec => 'app:db:test:prepare')

task :default => :spec

