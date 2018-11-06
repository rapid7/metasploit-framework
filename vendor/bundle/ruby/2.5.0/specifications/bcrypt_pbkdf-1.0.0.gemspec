# -*- encoding: utf-8 -*-
# stub: bcrypt_pbkdf 1.0.0 ruby lib
# stub: ext/mri/extconf.rb

Gem::Specification.new do |s|
  s.name = "bcrypt_pbkdf".freeze
  s.version = "1.0.0"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Miklos Fazekas".freeze]
  s.date = "2016-11-25"
  s.description = "    This gem implements bcrypt_pdkfd (a variant of PBKDF2 with bcrypt-based PRF)\n".freeze
  s.email = "mfazekas@szemafor.com".freeze
  s.extensions = ["ext/mri/extconf.rb".freeze]
  s.extra_rdoc_files = ["README.md".freeze, "COPYING".freeze, "CHANGELOG.md".freeze, "lib/bcrypt_pbkdf.rb".freeze]
  s.files = ["CHANGELOG.md".freeze, "COPYING".freeze, "README.md".freeze, "ext/mri/extconf.rb".freeze, "lib/bcrypt_pbkdf.rb".freeze]
  s.homepage = "https://github.com/net-ssh/bcrypt_pbkdf-ruby".freeze
  s.licenses = ["MIT".freeze]
  s.rdoc_options = ["--title".freeze, "bcrypt_pbkdf".freeze, "--line-numbers".freeze, "--inline-source".freeze, "--main".freeze, "README.md".freeze]
  s.rubygems_version = "2.7.7".freeze
  s.summary = "OpenBSD's bcrypt_pdkfd (a variant of PBKDF2 with bcrypt-based PRF)".freeze

  s.installed_by_version = "2.7.7" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<rake-compiler>.freeze, ["~> 0.9.7"])
      s.add_development_dependency(%q<minitest>.freeze, [">= 5"])
      s.add_development_dependency(%q<rbnacl>.freeze, ["~> 3.3"])
      s.add_development_dependency(%q<rbnacl-libsodium>.freeze, ["~> 1.0.8"])
      s.add_development_dependency(%q<rdoc>.freeze, ["~> 3.12"])
      s.add_development_dependency(%q<rake-compiler-dock>.freeze, ["~> 0.5.3"])
    else
      s.add_dependency(%q<rake-compiler>.freeze, ["~> 0.9.7"])
      s.add_dependency(%q<minitest>.freeze, [">= 5"])
      s.add_dependency(%q<rbnacl>.freeze, ["~> 3.3"])
      s.add_dependency(%q<rbnacl-libsodium>.freeze, ["~> 1.0.8"])
      s.add_dependency(%q<rdoc>.freeze, ["~> 3.12"])
      s.add_dependency(%q<rake-compiler-dock>.freeze, ["~> 0.5.3"])
    end
  else
    s.add_dependency(%q<rake-compiler>.freeze, ["~> 0.9.7"])
    s.add_dependency(%q<minitest>.freeze, [">= 5"])
    s.add_dependency(%q<rbnacl>.freeze, ["~> 3.3"])
    s.add_dependency(%q<rbnacl-libsodium>.freeze, ["~> 1.0.8"])
    s.add_dependency(%q<rdoc>.freeze, ["~> 3.12"])
    s.add_dependency(%q<rake-compiler-dock>.freeze, ["~> 0.5.3"])
  end
end
