# enconding: utf-8
require 'thor/rake_compat'

class Default < Thor
  include Thor::RakeCompat

  require 'rspec/core/rake_task'
  RSpec::Core::RakeTask.new(:spec)

  require 'bundler'
  Bundler::GemHelper.install_tasks

  require 'rdoc/task'
  if defined?(RDoc)
    RDoc::Task.new do |rdoc|
      rdoc.main     = 'README.md'
      rdoc.rdoc_dir = 'rdoc'
      rdoc.title    = 'thor'
      rdoc.rdoc_files.include('README.md', 'LICENSE', 'CHANGELOG.rdoc', 'Thorfile')
      rdoc.rdoc_files.include('lib/**/*.rb')
      rdoc.options << '--line-numbers' << '--inline-source'
    end
  end
end
