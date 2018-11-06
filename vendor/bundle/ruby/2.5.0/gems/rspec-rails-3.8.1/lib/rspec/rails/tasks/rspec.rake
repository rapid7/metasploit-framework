require 'rspec/core/rake_task'
if default = Rake.application.instance_variable_get('@tasks')['default']
  default.prerequisites.delete('test')
end

task :default => :spec

task :stats => "spec:statsetup"

desc "Run all specs in spec directory (excluding plugin specs)"
RSpec::Core::RakeTask.new(:spec => "spec:prepare")

namespace :spec do
  types = begin
            dirs = Dir['./spec/**/*_spec.rb'].
              map { |f| f.sub(/^\.\/(spec\/\w+)\/.*/, '\\1') }.
              uniq.
              select { |f| File.directory?(f) }
            Hash[dirs.map { |d| [d.split('/').last, d] }]
          end

  task :prepare do
    ENV['RACK_ENV'] = ENV['RAILS_ENV'] = 'test'
    if Rails.configuration.generators.options[:rails][:orm] == :active_record
      if Rake::Task.task_defined?("test:prepare")
        Rake::Task["test:prepare"].invoke
      end
    end
  end

  types.each do |type, dir|
    desc "Run the code examples in #{dir}"
    RSpec::Core::RakeTask.new(type => "spec:prepare") do |t|
      t.pattern = "./#{dir}/**/*_spec.rb"
    end
  end

  # RCov task only enabled for Ruby 1.8
  if RUBY_VERSION < '1.9'
    desc "Run all specs with rcov"
    RSpec::Core::RakeTask.new(:rcov => "spec:prepare") do |t|
      t.rcov = true
      t.pattern = "./spec/**/*_spec.rb"
      t.rcov_opts = '--exclude /gems/,/Library/,/usr/,lib/tasks,.bundle,config,/lib/rspec/,/lib/rspec-,spec'
    end
  end

  task :statsetup do
    require 'rails/code_statistics'
    types.each do |type, dir|
      name = type.singularize.capitalize

      ::STATS_DIRECTORIES << ["#{name} specs", dir]
      ::CodeStatistics::TEST_TYPES << "#{name} specs"
    end
  end
end
