#!/usr/bin/env rake
require 'bundler/gem_tasks'

require 'rspec/core/rake_task'

spec = Gem::Specification.load('pg_array_parser.gemspec')

if RUBY_PLATFORM =~ /java/
  require 'rake/javaextensiontask'
  Rake::JavaExtensionTask.new('pg_array_parser', spec)
else
  require 'rake/extensiontask'
  Rake::ExtensionTask.new('pg_array_parser', spec)
end

task :install => :compile
task :spec => :install

RSpec::Core::RakeTask.new(:spec)

task :default => :spec
