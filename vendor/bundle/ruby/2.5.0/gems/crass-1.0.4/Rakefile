require 'bundler'
require 'rake/testtask'

Bundler::GemHelper.install_tasks

Rake::TestTask.new
task :default => [:test]
task :test => :set_rubyopts

task :set_rubyopts do
  ENV['RUBYOPT'] ||= ""
  ENV['RUBYOPT'] += " -w"

  if RUBY_ENGINE == "ruby" && RUBY_VERSION >= "2.3"
    ENV['RUBYOPT'] += " --enable-frozen-string-literal --debug=frozen-string-literal"
  end
end

task :'pull-css-tests' do
  sh 'git subtree pull -P test/css-parsing-tests https://github.com/SimonSapin/css-parsing-tests.git master --squash'
end
