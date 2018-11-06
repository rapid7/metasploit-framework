require 'rake/testtask'

Rake::TestTask.new(:test_pure) do |t|
  t.libs << 'tests'
  t.libs << 'lib'
  t.test_files = Dir.glob('tests/**/test_pure*.rb') + Dir.glob('tests/**/test_ssl*.rb')
  t.warning = true
end

task :test_em_pure_ruby do
  ENV['EM_PURE_RUBY'] = 'true'
  Rake::Task['test_pure'].execute
end
