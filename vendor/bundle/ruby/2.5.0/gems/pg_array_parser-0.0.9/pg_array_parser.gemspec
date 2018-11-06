# -*- encoding: utf-8 -*-
require File.expand_path('../lib/pg_array_parser/version', __FILE__)

Gem::Specification.new do |gem|
  gem.authors       = ["Dan McClain"]
  gem.email         = ["git@danmcclain.net"]
  gem.description   = %q{Simple library to parse PostgreSQL arrays into a array of strings}
  gem.summary       = %q{Converts PostgreSQL array strings into arrays of strings}
  gem.homepage      = "https://github.com/dockyard/pg_array_parser"

  gem.files         = [ 'CHANGELOG.md',
                        'Gemfile',
                        'README.md',
                        'Rakefile',
                        'lib/pg_array_parser.rb',
                        'lib/pg_array_parser/version.rb',
                        'pg_array_parser.gemspec',
                        'spec/parser_spec.rb',
                        'spec/spec_helper.rb'
                      ]

  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  if RUBY_PLATFORM =~ /java/
    gem.platform = 'java'
    gem.files << 'ext/pg_array_parser/PgArrayParserEngine.java'
    gem.files << 'ext/pg_array_parser/PgArrayParserEngineService.java'
    gem.files << 'lib/pg_array_parser.jar'
  else
    gem.files << 'ext/pg_array_parser/pg_array_parser.c'
    gem.extensions    = ['ext/pg_array_parser/extconf.rb']
  end
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.name          = "pg_array_parser"
  gem.require_paths = ["lib"]
  gem.version       = PgArrayParser::VERSION

  gem.add_development_dependency 'rspec', '~> 2.11.0'
  gem.add_development_dependency 'rake', '~> 0.9.2.2'
  gem.add_development_dependency 'rake-compiler'
end
