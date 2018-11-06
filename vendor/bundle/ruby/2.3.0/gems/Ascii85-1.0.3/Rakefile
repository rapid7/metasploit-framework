require 'bundler'
Bundler::GemHelper.install_tasks

require 'rake/testtask'

Rake::TestTask.new do |t|
  t.test_files = FileList['spec/**/*_spec.rb']
end

task :specs   => :test
task :tests   => :test
task :default => :test
