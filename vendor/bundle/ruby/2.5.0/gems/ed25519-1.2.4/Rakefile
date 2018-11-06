# frozen_string_literal: true

require "bundler/gem_tasks"

require "rake/clean"
CLEAN.include("**/*.o", "**/*.so", "**/*.bundle", "*.jar", "pkg", "tmp")

if defined? JRUBY_VERSION
  require "rake/javaextensiontask"
  Rake::JavaExtensionTask.new("ed25519_jruby") do |ext|
    ext.ext_dir = "ext/ed25519_jruby"
  end
else
  require "rake/extensiontask"

  Rake::ExtensionTask.new("ed25519_ref10") do |ext|
    ext.ext_dir = "ext/ed25519_ref10"
  end
end

require "rspec/core/rake_task"
RSpec::Core::RakeTask.new

require "rubocop/rake_task"
RuboCop::RakeTask.new

task default: %w[compile spec rubocop]
