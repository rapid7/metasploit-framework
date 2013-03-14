require 'rake'
require 'rake/clean'
require 'rake/testtask'

CLEAN.include("**/*.gem", "**/*.rbc")

namespace :gem do
  desc 'Create the windows-api gem'
  task :create => [:clean] do
    spec = eval(IO.read('windows-api.gemspec'))
    Gem::Builder.new(spec).build
  end

  desc 'Install the windows-api gem'
  task :install => [:create] do
    file = Dir["*.gem"].first
    sh "gem install #{file}"
  end
end

Rake::TestTask.new do |test|
  test.warning = true
  test.verbose = true
end

task :default => :test
