require 'rubygems'
require 'bundler'
Bundler::GemHelper.install_tasks

require 'rspec/core/rake_task'
RSpec::Core::RakeTask.new(:spec) do |spec|
  spec.rspec_opts = ["--color", "--backtrace", "--format", "documentation"]
  spec.verbose = true
end

task :default => :spec
