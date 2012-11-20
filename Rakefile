require 'bundler/setup'

require 'rspec/core/rake_task'
require 'yard'

RSpec::Core::RakeTask.new(:spec)

task :default => :spec

namespace :yard do
  yard_files = [
      # Ruby source files first
      'lib/msf/**/*.rb',
      'lib/rex/**/*.rb',
      # Anything after '-' is a normal documentation, not source
      '-',
      'COPYING',
      'HACKING',
      'THIRD-PARTY.md'
  ]
  yard_options = [
      # include documentation for protected methods for developers extending the code.
      '--protected'
  ]

  YARD::Rake::YardocTask.new(:doc) do |t|
    t.files = yard_files
    # --no-stats here as 'stats' task called after will print fuller stats
    t.options = yard_options + ['--no-stats']

    t.after = Proc.new {
      Rake::Task['yard:stats'].execute
    }
  end

  desc "Shows stats for YARD Documentation including listing undocumented modules, classes, constants, and methods"
  task :stats => :environment do
    stats = YARD::CLI::Stats.new
    yard_arguments = yard_options + ['--compact', '--list-undoc'] + yard_files
    stats.run(*yard_arguments)
  end
end

# @todo Figure out how to just clone description from yard:doc
desc "Generate YARD documentation"
# allow calling namespace to as a task that goes to default task for namespace
task :yard => ['yard:doc']
