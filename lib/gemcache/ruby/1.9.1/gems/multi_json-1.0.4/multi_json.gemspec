# encoding: utf-8
require File.expand_path("../lib/multi_json/version", __FILE__)

Gem::Specification.new do |gem|
  gem.add_development_dependency 'rake', '~> 0.9'
  gem.add_development_dependency 'rdoc', '~> 3.9'
  gem.add_development_dependency 'rspec', '~> 2.6'
  gem.add_development_dependency 'simplecov', '~> 0.4'
  gem.authors = ["Michael Bleigh", "Josh Kalderimis", "Erik Michaels-Ober"]
  gem.description = %q{A gem to provide swappable JSON backends utilizing Yajl::Ruby, the JSON gem, JSON pure, or a vendored version of okjson.}
  gem.email = ['michael@intridea.com', 'josh.kalderimis@gmail.com', 'sferik@gmail.com']
  gem.extra_rdoc_files = ['LICENSE.md', 'README.md']
  gem.files = Dir['LICENSE.md', 'README.md', 'Rakefile', 'multi_json.gemspec', 'Gemfile', '.document', '.rspec', '.travis.yml' ,'spec/**/*', 'lib/**/*']
  gem.homepage = 'http://github.com/intridea/multi_json'
  gem.name = 'multi_json'
  gem.rdoc_options = ["--charset=UTF-8"]
  gem.require_paths = ['lib']
  gem.required_rubygems_version = Gem::Requirement.new(">= 1.3.6")
  gem.summary = %q{A gem to provide swappable JSON backends.}
  gem.test_files = Dir['spec/**/*']
  gem.version = MultiJson::VERSION
end
