require 'rake/testtask'

Rake::TestTask.new(:test) do |t|
  t.libs << "tests"
  t.libs << "lib"
  t.pattern = 'tests/**/test_*.rb'
  t.warning = true
end
