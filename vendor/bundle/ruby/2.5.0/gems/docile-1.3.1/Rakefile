require "rake/clean"
require "bundler/gem_tasks"
require "rspec/core/rake_task"
require File.expand_path("on_what", File.dirname(__FILE__))

# Default task for `rake` is to run rspec
task :default => [:spec]

# Use default rspec rake task
RSpec::Core::RakeTask.new

# Configure `rake clobber` to delete all generated files
CLOBBER.include("pkg", "doc", "coverage")

# To limit needed compatibility with versions of dependencies, only configure
#   yard doc generation when *not* on Travis, JRuby, or < 2.0
if !on_travis? && !on_jruby? && !on_less_than_2_0?
  require "github/markup"
  require "redcarpet"
  require "yard"
  require "yard/rake/yardoc_task"

  YARD::Rake::YardocTask.new do |t|
    OTHER_PATHS = %w()
    t.files   = ["lib/**/*.rb", OTHER_PATHS]
    t.options = %w(--markup-provider=redcarpet --markup=markdown --main=README.md)
  end
end
