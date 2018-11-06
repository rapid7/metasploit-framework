require 'rubygems/package_task'
require 'rake/testtask'
require 'bundler/gem_tasks'

spec = Gem::Specification.load "rb-readline.gemspec"

Gem::PackageTask.new(spec) do |pkg|
end

Rake::TestTask.new do |t|
  t.libs << "test"

  t.warning = true
  t.verbose = true
end

desc "Install the gem locally"
task :install => :gem do
  Dir.chdir(File.dirname(__FILE__)) do
    sh %{gem install --local pkg/#{spec.name}-#{spec.version}.gem}
  end
end

desc "The default is to test everything."
task :default => :test
