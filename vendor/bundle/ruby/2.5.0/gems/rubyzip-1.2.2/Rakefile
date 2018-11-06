require 'bundler/gem_tasks'
require 'rake/testtask'

task default: :test

Rake::TestTask.new(:test) do |test|
  test.libs << 'lib'
  test.libs << 'test'
  test.pattern = 'test/**/*_test.rb'
  test.verbose = true
end

# Rake::TestTask.new(:zip64_full_test) do |test|
#  test.libs << File.join(File.dirname(__FILE__), 'lib')
#  test.libs << File.join(File.dirname(__FILE__), 'test')
#  test.pattern = File.join(File.dirname(__FILE__), 'test/zip64_full_test.rb')
#  test.verbose = true
# end
