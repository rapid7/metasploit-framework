require 'rubygems'
require 'bundler'
Bundler.setup

require 'rake'
require 'rake/testtask'

require 'appraisal'

desc 'Default: run all tests.'
task :default => :test

desc "Test state_machine."
Rake::TestTask.new(:test) do |t|
  integration = %w(active_model active_record data_mapper mongoid mongo_mapper sequel).detect do |name|
    Bundler.default_gemfile.to_s.include?(name)
  end
  
  t.libs << 'lib'
  t.test_files = integration ? Dir["test/unit/integrations/#{integration}_test.rb"] : Dir['test/{functional,unit}/*_test.rb'] + ['test/unit/integrations/base_test.rb']
  t.verbose = true
end

namespace :appraisal do
  desc "Run the given task for a particular integration's appraisals"
  task :integration do
    integration = ENV['INTEGRATION']
    
    Appraisal::File.each do |appraisal|
      if appraisal.name.include?(integration)
        appraisal.install
        Appraisal::Command.from_args(appraisal.gemfile_path).run
      end
    end
    
    exit
  end
end

load File.dirname(__FILE__) + '/lib/tasks/state_machine.rake'
