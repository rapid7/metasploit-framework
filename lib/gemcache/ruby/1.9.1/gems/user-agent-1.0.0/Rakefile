
$:.unshift 'lib'
require 'user-agent'
require 'rubygems'
require 'rake'
require 'echoe'

Echoe.new "user-agent", Agent::VERSION do |p|
  p.author = "TJ Holowaychuk"
  p.email = "tj@vision-media.ca"
  p.summary = "User agent parser"
  p.runtime_dependencies = []
end

Dir['tasks/**/*.rake'].sort.each { |f| load f }