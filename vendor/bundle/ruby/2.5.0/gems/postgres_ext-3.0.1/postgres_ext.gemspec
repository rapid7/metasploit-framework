# -*- encoding: utf-8 -*-
require File.expand_path('../lib/postgres_ext/version', __FILE__)

Gem::Specification.new do |gem|
  gem.authors       = ["Dan McClain"]
  gem.email         = ["git@danmcclain.net"]
  gem.description   = %q{Adds missing native PostgreSQL data types to ActiveRecord and convenient querying extensions for ActiveRecord and Arel}
  gem.summary       = %q{Extends ActiveRecord to handle native PostgreSQL data types}
  gem.homepage      = 'https://github.com/danmcclain/postgres_ext'
  gem.licenses      = ['MIT']

  gem.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  gem.files         = `git ls-files`.split("\n")
  gem.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  gem.name          = "postgres_ext"
  gem.require_paths = ["lib"]
  gem.version       = PostgresExt::VERSION

  gem.add_dependency 'activerecord', '~> 4.0'
  gem.add_dependency 'arel', '>= 4.0.1'
  gem.add_dependency 'pg_array_parser', '~> 0.0.9'

  gem.add_development_dependency 'rake', '~> 10.1.0'
  gem.add_development_dependency 'minitest'
  gem.add_development_dependency 'm'
  gem.add_development_dependency 'bourne', '~> 1.3.0'
  gem.add_development_dependency 'database_cleaner'
  gem.add_development_dependency 'dotenv'
  if RUBY_PLATFORM =~ /java/
      gem.add_development_dependency 'activerecord-jdbcpostgresql-adapter', '1.3.0.beta2'
  else
      gem.add_development_dependency 'pg', '~> 0.13'
  end
end
