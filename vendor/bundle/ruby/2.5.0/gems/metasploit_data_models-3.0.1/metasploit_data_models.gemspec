# -*- encoding: utf-8 -*-
$LOAD_PATH.push File.expand_path('../lib', __FILE__)
require 'metasploit_data_models/version'

Gem::Specification.new do |s|
  s.name        = 'metasploit_data_models'
  s.version     = MetasploitDataModels::VERSION
  s.authors     = [
      'Samuel Huckins',
      'Luke Imhoff',
      "David 'thelightcosine' Maloney",
      "Trevor 'burlyscudd' Rosen"
  ]
  s.email       = [
      'shuckins@rapid7.com',
      'luke_imhoff@rapid7.com',
      'dmaloney@rapid7.com',
      'trevor_rosen@rapid7.com'
  ]
  s.homepage    = ""
  s.summary     = %q{Database code for MSF and Metasploit Pro}
  s.description = %q{Implements minimal ActiveRecord models and database helper code used in both the Metasploit Framework (MSF) and Metasploit commercial editions.}

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = %w{app/models app/validators lib}

  s.required_ruby_version = '>= 2.1'

  # ---- Dependencies ----
  # documentation
  s.add_development_dependency 'metasploit-yard'
  s.add_development_dependency 'yard-activerecord'
  # embed ERDs on index, namespace Module and Class<ActiveRecord::Base> pages
  s.add_development_dependency 'yard-metasploit-erd'

  s.add_development_dependency 'rake'

  # documentation
  # @note 0.8.7.4 has a bug where attribute writers show up as undocumented
  s.add_development_dependency 'yard', '< 0.8.7.4'
  # debugging
  s.add_development_dependency 'pry'


  s.add_runtime_dependency 'activerecord', '~>4.2.6'
  s.add_runtime_dependency 'activesupport', '~>4.2.6'
  s.add_runtime_dependency 'metasploit-concern'
  s.add_runtime_dependency 'metasploit-model'
  s.add_runtime_dependency 'railties', '~>4.2.6'

  # os fingerprinting
  s.add_runtime_dependency 'recog', '~> 2.0'

  # arel-helpers: Useful tools to help construct database queries with ActiveRecord and Arel.
  s.add_runtime_dependency 'arel-helpers'

  # Fixes a problem with arel not being able to visit IPAddr nodes
  s.add_runtime_dependency 'postgres_ext'

  if RUBY_PLATFORM =~ /java/
    # markdown formatting for yard
    s.add_development_dependency 'kramdown'

    s.add_runtime_dependency 'jdbc-postgres'
    s.add_runtime_dependency 'activerecord-jdbcpostgresql-adapter'

    s.platform = Gem::Platform::JAVA
  else
    # markdown formatting for yard
    s.add_development_dependency 'redcarpet'

    # bound to 0.20 for Activerecord 4.2.8 deprecation warnings:
    # https://github.com/ged/ruby-pg/commit/c90ac644e861857ae75638eb6954b1cb49617090
    s.add_runtime_dependency 'pg', "0.20.0"

    s.platform = Gem::Platform::RUBY
  end
end
