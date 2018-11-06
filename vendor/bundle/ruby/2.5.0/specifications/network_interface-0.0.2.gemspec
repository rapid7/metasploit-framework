# -*- encoding: utf-8 -*-
# stub: network_interface 0.0.2 ruby lib
# stub: ext/network_interface_ext/extconf.rb

Gem::Specification.new do |s|
  s.name = "network_interface".freeze
  s.version = "0.0.2"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Brandon Turner".freeze, "Lance Sanchez".freeze]
  s.date = "2017-08-29"
  s.description = "\n     This gem was originally added to the Metasploit Pcaprub gem. It's been spun\n     out into its own gem for anyone who might want to programmatically get\n     information on their network interfaces. ".freeze
  s.email = ["lance.sanchez@rapid7.com".freeze, "brandon_turner@rapid7.com".freeze]
  s.executables = ["list_interfaces.rb".freeze]
  s.extensions = ["ext/network_interface_ext/extconf.rb".freeze]
  s.files = ["bin/list_interfaces.rb".freeze, "ext/network_interface_ext/extconf.rb".freeze]
  s.homepage = "https://github.com/rapid7/network_interface".freeze
  s.licenses = ["MIT".freeze]
  s.rubygems_version = "2.7.7".freeze
  s.summary = "A cross platform gem to help get network interface information".freeze

  s.installed_by_version = "2.7.7" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<bundler>.freeze, ["~> 1.3"])
      s.add_development_dependency(%q<rake>.freeze, [">= 0"])
      s.add_development_dependency(%q<rake-compiler>.freeze, [">= 0"])
      s.add_development_dependency(%q<rspec>.freeze, [">= 0"])
    else
      s.add_dependency(%q<bundler>.freeze, ["~> 1.3"])
      s.add_dependency(%q<rake>.freeze, [">= 0"])
      s.add_dependency(%q<rake-compiler>.freeze, [">= 0"])
      s.add_dependency(%q<rspec>.freeze, [">= 0"])
    end
  else
    s.add_dependency(%q<bundler>.freeze, ["~> 1.3"])
    s.add_dependency(%q<rake>.freeze, [">= 0"])
    s.add_dependency(%q<rake-compiler>.freeze, [">= 0"])
    s.add_dependency(%q<rspec>.freeze, [">= 0"])
  end
end
