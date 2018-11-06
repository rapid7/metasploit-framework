# encoding: UTF-8

require 'rubygems' unless ENV['NO_RUBYGEMS']

require 'bundler'
require 'rspec/core/rake_task'
require 'rubygems/package_task'

require './lib/arel-helpers'

Bundler::GemHelper.install_tasks

task default: :spec

desc 'Run specs'
RSpec::Core::RakeTask.new do |t|
  t.pattern = './spec/**/*_spec.rb'
end

task :console do
  $:.push(File.dirname(__FILE__))

  require 'spec/env'
  require 'pry-byebug'

  ArelHelpers::Env.establish_connection
  ArelHelpers::Env.reset
  ArelHelpers::Env.migrate

  Pry.start
end
