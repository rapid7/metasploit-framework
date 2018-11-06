require 'bundler'
Bundler.setup
Bundler::GemHelper.install_tasks

require 'rake/clean'
require 'rake/testtask'

task :clobber do
  rm_rf 'pkg'
end

Rake::TestTask.new do |t|
  t.pattern = "test/**/*_test.rb"
end

task default: :test
