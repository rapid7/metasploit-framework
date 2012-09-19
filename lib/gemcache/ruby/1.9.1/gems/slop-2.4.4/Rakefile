begin
  require 'bundler/gem_tasks'
rescue LoadError
end

require 'rake/testtask'

Rake::TestTask.new do |t|
  t.libs << 'test'
  t.test_files = Dir['test/*_test.rb']
end

task :default => :test
