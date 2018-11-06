require 'rake/testtask'

ENV['RUN_EXTRA_TASK'] = 'TRUE' if
  RUBY_VERSION >= "1.9.3" && defined?(RUBY_ENGINE) && RUBY_ENGINE == 'ruby'

if ENV['RUN_EXTRA_TASK'] == 'TRUE'
  require 'rdoc/task'

  Rake::RDocTask.new do |rd|
    rd.rdoc_files.include("lib/**/*.rb")
    rd.rdoc_files.exclude("lib/Dnsruby/iana_ports.rb")
    rd.main = "Dnsruby"
    #  rd.options << "--ri"
  end

  require 'coveralls/rake/task'
  Coveralls::RakeTask.new
end

def create_task(task_name, test_suite_filespec)
  Rake::TestTask.new do |t|
    t.name = task_name
    t.test_files = FileList[test_suite_filespec]
    t.verbose = true
  end
end

create_task(:test,         'test/ts_dnsruby.rb')
create_task(:test_offline, 'test/ts_offline.rb')
create_task(:test_online,  'test/ts_online.rb')
create_task(:soak,         'test/tc_soak.rb')
create_task(:message,      'test/tc_message.rb')
create_task(:cache,         'test/tc_cache.rb')
create_task(:pipe,          'test/tc_tcp_pipelining.rb')
