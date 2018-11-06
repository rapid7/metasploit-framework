# -*- encoding: utf-8 -*-
# stub: pcaprub 0.13.0 ruby lib
# stub: ext/pcaprub_c/extconf.rb

Gem::Specification.new do |s|
  s.name = "pcaprub".freeze
  s.version = "0.13.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["shadowbq".freeze, "crondaemon".freeze, "jmcavinee".freeze, "unmarshal".freeze]
  s.date = "2018-07-26"
  s.description = "libpcap bindings for Ruby 2.x".freeze
  s.email = "shadowbq@gmail.com".freeze
  s.extensions = ["ext/pcaprub_c/extconf.rb".freeze]
  s.extra_rdoc_files = ["FAQ.rdoc".freeze, "LICENSE".freeze, "README.rdoc".freeze, "USAGE.rdoc".freeze, "ext/pcaprub_c/pcaprub.c".freeze]
  s.files = ["FAQ.rdoc".freeze, "LICENSE".freeze, "README.rdoc".freeze, "USAGE.rdoc".freeze, "ext/pcaprub_c/extconf.rb".freeze, "ext/pcaprub_c/pcaprub.c".freeze]
  s.homepage = "https://github.com/pcaprub/pcaprub".freeze
  s.licenses = ["LGPL-2.1".freeze]
  s.required_ruby_version = Gem::Requirement.new("~> 2.0".freeze)
  s.requirements = ["libpcap".freeze]
  s.rubygems_version = "2.7.7".freeze
  s.summary = "libpcap bindings for ruby".freeze

  s.installed_by_version = "2.7.7" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<bundler>.freeze, ["~> 1.3"])
      s.add_development_dependency(%q<rake>.freeze, [">= 0.9.2", "~> 0.9"])
      s.add_development_dependency(%q<rake-compiler>.freeze, [">= 0.6.0", "~> 0.6"])
      s.add_development_dependency(%q<shoulda-context>.freeze, ["~> 1.1", "~> 1.1.6"])
      s.add_development_dependency(%q<minitest>.freeze, [">= 4.7.0", "~> 4.7"])
    else
      s.add_dependency(%q<bundler>.freeze, ["~> 1.3"])
      s.add_dependency(%q<rake>.freeze, [">= 0.9.2", "~> 0.9"])
      s.add_dependency(%q<rake-compiler>.freeze, [">= 0.6.0", "~> 0.6"])
      s.add_dependency(%q<shoulda-context>.freeze, ["~> 1.1", "~> 1.1.6"])
      s.add_dependency(%q<minitest>.freeze, [">= 4.7.0", "~> 4.7"])
    end
  else
    s.add_dependency(%q<bundler>.freeze, ["~> 1.3"])
    s.add_dependency(%q<rake>.freeze, [">= 0.9.2", "~> 0.9"])
    s.add_dependency(%q<rake-compiler>.freeze, [">= 0.6.0", "~> 0.6"])
    s.add_dependency(%q<shoulda-context>.freeze, ["~> 1.1", "~> 1.1.6"])
    s.add_dependency(%q<minitest>.freeze, [">= 4.7.0", "~> 4.7"])
  end
end
