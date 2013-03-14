require "rubygems"


require 'rspec/core'
require "rspec/core/rake_task"

RSpec::Core::RakeTask.new do |t|
  t.pattern = "./**/*_spec.rb"
  t.ruby_opts = "-w"
end

task :default => :spec

# desc "Run all specs in spec directory with RCov"
# RSpec::Core::RakeTask.new(:rcov) do |t|
#   t.libs << 'lib'
#   t.libs << 'spec'
#   t.warning = true
#   t.rcov = true
#   t.rcov_opts = ['-x spec']
# end

desc "Generate RDoc"
task :docs do
  FileUtils.rm_rf("doc")
  require "rack/test"
  system "hanna --title 'Rack::Test #{Rack::Test::VERSION} API Documentation'"
end

desc 'Removes trailing whitespace'
task :whitespace do
  sh %{find . -name '*.rb' -exec sed -i '' 's/ *$//g' {} \\;}
end
