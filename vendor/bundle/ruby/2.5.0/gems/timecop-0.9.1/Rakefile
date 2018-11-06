require 'bundler/setup'
require 'bundler/gem_tasks'
require 'rake/testtask'
require 'rdoc/task'

Rake::RDocTask.new do |rdoc|
  if File.exist?('VERSION')
    version = File.read('VERSION')
  else
    version = ""
  end

  rdoc.rdoc_dir = 'rdoc'
  rdoc.options << '--line-numbers' << '--inline-source'
  rdoc.title = "timecop #{version}"
  rdoc.rdoc_files.include('README*')
  rdoc.rdoc_files.include('History.rdoc')
  rdoc.rdoc_files.include('lib/**/*.rb')
end

task :test do
  failed = Dir["test/*_test.rb"].map do |test|
    command = "ruby #{test}"
    puts
    puts command
    command unless system(command)
  end.compact
  if failed.any?
    abort "#{failed.count} Tests failed\n#{failed.join("\n")}"
  end
end

desc 'Default: run tests'
task :default => [:test]
