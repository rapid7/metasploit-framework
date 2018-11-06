
begin
  require 'rspec/core/rake_task'
rescue LoadError
  $stderr.puts "rspec not available, so can't set up spec tasks."
else
  RSpec::Core::RakeTask.new

  task :default => :spec
end

