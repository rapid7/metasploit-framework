require 'rubygems'
require 'bundler'
Bundler.setup(:default, :development)
require 'rake'
require 'jeweler'
require 'rspec/core/rake_task'
require File.expand_path("../lib/treetop/version", __FILE__)

Jeweler::Tasks.new do |gem|
  gem.name = "treetop"
  gem.version = Treetop::VERSION::STRING
  gem.author = "Nathan Sobo"
  gem.license = "MIT"
  gem.email = "cliffordheath@gmail.com"
  gem.homepage = "http://functionalform.blogspot.com"
  gem.platform = Gem::Platform::RUBY
  gem.summary = "A Ruby-based text parsing and interpretation DSL"
  gem.files = ["LICENSE", "README.md", "Rakefile", "treetop.gemspec", "{spec,lib,bin,doc,examples}/**/*"].map{|p| Dir[p]}.flatten
  gem.bindir = "bin"
  gem.executables = ["tt"]
  gem.require_path = "lib"
  gem.autorequire = "treetop"
  gem.has_rdoc = false
  gem.add_dependency "polyglot", ">= 0.3.1"
end
Jeweler::RubygemsDotOrgTasks.new

task :default => :spec
RSpec::Core::RakeTask.new do |t|
  t.pattern = 'spec/**/*spec.rb'
  # t.libs << 'spec' # @todo not sure what this did in the original rspec 1.3
end

task :spec => 'lib/treetop/compiler/metagrammar.treetop'
file 'lib/treetop/compiler/metagrammar.treetop' do |t|
  unless $bootstrapped_gen_1_metagrammar
    load File.expand_path('../lib/treetop/bootstrap_gen_1_metagrammar.rb', __FILE__)
  end

  Treetop::Compiler::GrammarCompiler.new.compile(METAGRAMMAR_PATH)
end

task :version do
  puts RUBY_VERSION
end

desc 'Generate website files'
task :website_generate do
  `cd doc; ruby ./site.rb`
end

desc 'Upload website files'
task :website_upload do
  rubyforge_config_file = "#{ENV['HOME']}/.rubyforge/user-config.yml"
  rubyforge_config = YAML.load_file(rubyforge_config_file)
  `rsync -aCv doc/site/ #{rubyforge_config['username']}@rubyforge.org:/var/www/gforge-projects/treetop/`
end

desc 'Generate and upload website files'
task :website => [:website_generate, :website_upload]
