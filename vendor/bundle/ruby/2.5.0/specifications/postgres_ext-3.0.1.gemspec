# -*- encoding: utf-8 -*-
# stub: postgres_ext 3.0.1 ruby lib

Gem::Specification.new do |s|
  s.name = "postgres_ext".freeze
  s.version = "3.0.1"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Dan McClain".freeze]
  s.date = "2018-04-16"
  s.description = "Adds missing native PostgreSQL data types to ActiveRecord and convenient querying extensions for ActiveRecord and Arel".freeze
  s.email = ["git@danmcclain.net".freeze]
  s.homepage = "https://github.com/danmcclain/postgres_ext".freeze
  s.licenses = ["MIT".freeze]
  s.rubygems_version = "2.7.7".freeze
  s.summary = "Extends ActiveRecord to handle native PostgreSQL data types".freeze

  s.installed_by_version = "2.7.7" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<activerecord>.freeze, ["~> 4.0"])
      s.add_runtime_dependency(%q<arel>.freeze, [">= 4.0.1"])
      s.add_runtime_dependency(%q<pg_array_parser>.freeze, ["~> 0.0.9"])
      s.add_development_dependency(%q<rake>.freeze, ["~> 10.1.0"])
      s.add_development_dependency(%q<minitest>.freeze, [">= 0"])
      s.add_development_dependency(%q<m>.freeze, [">= 0"])
      s.add_development_dependency(%q<bourne>.freeze, ["~> 1.3.0"])
      s.add_development_dependency(%q<database_cleaner>.freeze, [">= 0"])
      s.add_development_dependency(%q<dotenv>.freeze, [">= 0"])
      s.add_development_dependency(%q<pg>.freeze, ["~> 0.13"])
    else
      s.add_dependency(%q<activerecord>.freeze, ["~> 4.0"])
      s.add_dependency(%q<arel>.freeze, [">= 4.0.1"])
      s.add_dependency(%q<pg_array_parser>.freeze, ["~> 0.0.9"])
      s.add_dependency(%q<rake>.freeze, ["~> 10.1.0"])
      s.add_dependency(%q<minitest>.freeze, [">= 0"])
      s.add_dependency(%q<m>.freeze, [">= 0"])
      s.add_dependency(%q<bourne>.freeze, ["~> 1.3.0"])
      s.add_dependency(%q<database_cleaner>.freeze, [">= 0"])
      s.add_dependency(%q<dotenv>.freeze, [">= 0"])
      s.add_dependency(%q<pg>.freeze, ["~> 0.13"])
    end
  else
    s.add_dependency(%q<activerecord>.freeze, ["~> 4.0"])
    s.add_dependency(%q<arel>.freeze, [">= 4.0.1"])
    s.add_dependency(%q<pg_array_parser>.freeze, ["~> 0.0.9"])
    s.add_dependency(%q<rake>.freeze, ["~> 10.1.0"])
    s.add_dependency(%q<minitest>.freeze, [">= 0"])
    s.add_dependency(%q<m>.freeze, [">= 0"])
    s.add_dependency(%q<bourne>.freeze, ["~> 1.3.0"])
    s.add_dependency(%q<database_cleaner>.freeze, [">= 0"])
    s.add_dependency(%q<dotenv>.freeze, [">= 0"])
    s.add_dependency(%q<pg>.freeze, ["~> 0.13"])
  end
end
