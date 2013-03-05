# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "method_source"
  s.version = "0.7.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["John Mair (banisterfiend)"]
  s.date = "2012-01-01"
  s.description = "retrieve the sourcecode for a method"
  s.email = "jrmair@gmail.com"
  s.files = [".gemtest", ".travis.yml", ".yardopts", "Gemfile", "LICENSE", "README.markdown", "Rakefile", "lib/method_source.rb", "lib/method_source/source_location.rb", "lib/method_source/version.rb", "method_source.gemspec", "test/test.rb", "test/test_helper.rb"]
  s.homepage = "http://banisterfiend.wordpress.com"
  s.require_paths = ["lib"]
  s.rubygems_version = "1.8.10"
  s.summary = "retrieve the sourcecode for a method"
  s.test_files = ["test/test.rb", "test/test_helper.rb"]

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<bacon>, ["~> 1.1.0"])
      s.add_development_dependency(%q<rake>, ["~> 0.9"])
    else
      s.add_dependency(%q<bacon>, ["~> 1.1.0"])
      s.add_dependency(%q<rake>, ["~> 0.9"])
    end
  else
    s.add_dependency(%q<bacon>, ["~> 1.1.0"])
    s.add_dependency(%q<rake>, ["~> 0.9"])
  end
end
