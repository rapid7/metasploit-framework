# -*- encoding: utf-8 -*-
# stub: sysrandom 1.0.5 ruby lib
# stub: ext/sysrandom/extconf.rb

Gem::Specification.new do |s|
  s.name = "sysrandom".freeze
  s.version = "1.0.5"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Tony Arcieri".freeze]
  s.bindir = "exe".freeze
  s.date = "2017-02-25"
  s.description = "Sysrandom generates secure random numbers using /dev/urandom, getrandom(), etc".freeze
  s.email = ["bascule@gmail.com".freeze]
  s.extensions = ["ext/sysrandom/extconf.rb".freeze]
  s.files = ["ext/sysrandom/extconf.rb".freeze]
  s.homepage = "https://github.com/cryptosphere/sysrandom".freeze
  s.licenses = ["ISC".freeze]
  s.rubygems_version = "2.7.7".freeze
  s.summary = "Secure random number generation using system RNG facilities".freeze

  s.installed_by_version = "2.7.7" if s.respond_to? :installed_by_version
end
