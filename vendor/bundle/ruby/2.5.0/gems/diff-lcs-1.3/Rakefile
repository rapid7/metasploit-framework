# -*- ruby encoding: utf-8 -*-

require 'rubygems'
require 'rspec'
require 'hoe'

Hoe.plugin :bundler
Hoe.plugin :doofus
Hoe.plugin :email unless ENV['CI'] or ENV['TRAVIS']
Hoe.plugin :gemspec2
Hoe.plugin :git
Hoe.plugin :travis

spec = Hoe.spec 'diff-lcs' do
  developer('Austin Ziegler', 'halostatue@gmail.com')

  require_ruby_version '>= 1.8'

  self.history_file = 'History.md'
  self.readme_file = 'README.rdoc'
  self.licenses = [ 'MIT', 'Artistic-2.0', 'GPL-2.0+' ]

  extra_dev_deps << ['hoe-doofus', '~> 1.0']
  extra_dev_deps << ['hoe-gemspec2', '~> 1.1']
  extra_dev_deps << ['hoe-git', '~> 1.6']
  extra_dev_deps << ['hoe-rubygems', '~> 1.0']
  extra_dev_deps << ['hoe-travis', '~> 1.2']
  extra_dev_deps << ['rspec', '>= 2.0', '< 4']
  extra_dev_deps << ['rake', '>= 10.0', '< 12']
  extra_dev_deps << ['rdoc', '>= 0']
end

unless Rake::Task.task_defined? :test
  task :test => :spec
  Rake::Task['travis'].prerequisites.replace(%w(spec))
end

if RUBY_VERSION >= '2.0' && RUBY_ENGINE == 'ruby'
  namespace :spec do
    task :coveralls do
      if ENV['CI'] or ENV['TRAVIS']
        ENV['COVERALLS'] = 'yes'
        Rake::Task['spec'].execute
      else
        Rake::Task['spec:coverage'].execute
      end
    end

    desc "Runs test coverage. Only works Ruby 2.0+ and assumes 'simplecov' is installed."
    task :coverage do
      ENV['COVERAGE'] = 'yes'
      Rake::Task['spec'].execute
    end
  end

  # Rake::Task['travis'].prerequisites.replace(%w(spec:coveralls))
end
