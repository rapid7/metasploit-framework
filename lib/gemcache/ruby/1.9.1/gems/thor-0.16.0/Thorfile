# encoding: utf-8
$:.unshift File.expand_path("../lib", __FILE__)

require 'bundler'
require 'thor/rake_compat'

class Default < Thor
  include Thor::RakeCompat
  Bundler::GemHelper.install_tasks

  desc "build", "Build thor-#{Thor::VERSION}.gem into the pkg directory"
  def build
    Rake::Task["build"].execute
  end

  desc "install", "Build and install thor-#{Thor::VERSION}.gem into system gems"
  def install
    Rake::Task["install"].execute
  end

  desc "release", "Create tag v#{Thor::VERSION} and build and push thor-#{Thor::VERSION}.gem to Rubygems"
  def release
    Rake::Task["release"].execute
  end

  desc "spec", "Run RSpec code examples"
  def spec
    exec "rspec --color --format=documentation spec"
  end
end
