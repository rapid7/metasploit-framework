require "bundler/gem_tasks"
require "rspec/core/rake_task"
require "rubocop/rake_task"
require "rake/clean"

unless defined? JRUBY_VERSION
  require "rake/extensiontask"
  Rake::ExtensionTask.new("sysrandom_ext") do |ext|
    ext.ext_dir = "ext/sysrandom"
  end
end

RSpec::Core::RakeTask.new(:spec)
RuboCop::RakeTask.new

default_tasks = %w(spec rubocop)
default_tasks.unshift("compile") unless defined?(JRUBY_VERSION)

task default: default_tasks

CLEAN.include "**/*.o", "**/*.so", "**/*.bundle", "pkg", "tmp"
