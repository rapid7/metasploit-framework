# -*- encoding: utf-8 -*-
# stub: rack-protection 1.5.5 ruby lib

Gem::Specification.new do |s|
  s.name = "rack-protection".freeze
  s.version = "1.5.5"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.require_paths = ["lib".freeze]
  s.authors = ["Konstantin Haase".freeze, "Alex Rodionov".freeze, "Patrick Ellis".freeze, "Jason Staten".freeze, "ITO Nobuaki".freeze, "Jeff Welling".freeze, "Matteo Centenaro".freeze, "Egor Homakov".freeze, "Florian Gilcher".freeze, "Fojas".freeze, "Igor Bochkariov".freeze, "Mael Clerambault".freeze, "Martin Mauch".freeze, "Renne Nissinen".freeze, "SAKAI, Kazuaki".freeze, "Stanislav Savulchik".freeze, "Steve Agalloco".freeze, "TOBY".freeze, "Thais Camilo and Konstantin Haase".freeze, "Vipul A M".freeze, "Akzhan Abdulin".freeze, "brookemckim".freeze, "Bj\u00F8rge N\u00E6ss".freeze, "Chris Heald".freeze, "Chris Mytton".freeze, "Corey Ward".freeze, "Dario Cravero".freeze, "David Kellum".freeze]
  s.date = "2018-03-07"
  s.description = "You should use protection!".freeze
  s.email = ["konstantin.mailinglists@googlemail.com".freeze, "p0deje@gmail.com".freeze, "jstaten07@gmail.com".freeze, "patrick@soundcloud.com".freeze, "jeff.welling@gmail.com".freeze, "bugant@gmail.com".freeze, "daydream.trippers@gmail.com".freeze, "florian.gilcher@asquera.de".freeze, "developer@fojasaur.us".freeze, "ujifgc@gmail.com".freeze, "mael@clerambault.fr".freeze, "martin.mauch@gmail.com".freeze, "rennex@iki.fi".freeze, "kaz.july.7@gmail.com".freeze, "s.savulchik@gmail.com".freeze, "steve.agalloco@gmail.com".freeze, "toby.net.info.mail+git@gmail.com".freeze, "dev+narwen+rkh@rkh.im".freeze, "vipulnsward@gmail.com".freeze, "akzhan.abdulin@gmail.com".freeze, "brooke@digitalocean.com".freeze, "bjoerge@bengler.no".freeze, "cheald@gmail.com".freeze, "self@hecticjeff.net".freeze, "coreyward@me.com".freeze, "dario@uxtemple.com".freeze, "dek-oss@gravitext.com".freeze, "homakov@gmail.com".freeze]
  s.homepage = "http://github.com/rkh/rack-protection".freeze
  s.licenses = ["MIT".freeze]
  s.rubygems_version = "2.7.7".freeze
  s.summary = "You should use protection!".freeze

  s.installed_by_version = "2.7.7" if s.respond_to? :installed_by_version

  if s.respond_to? :specification_version then
    s.specification_version = 4

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<rack>.freeze, [">= 0"])
      s.add_development_dependency(%q<rack-test>.freeze, [">= 0"])
      s.add_development_dependency(%q<rspec>.freeze, ["~> 2.0"])
    else
      s.add_dependency(%q<rack>.freeze, [">= 0"])
      s.add_dependency(%q<rack-test>.freeze, [">= 0"])
      s.add_dependency(%q<rspec>.freeze, ["~> 2.0"])
    end
  else
    s.add_dependency(%q<rack>.freeze, [">= 0"])
    s.add_dependency(%q<rack-test>.freeze, [">= 0"])
    s.add_dependency(%q<rspec>.freeze, ["~> 2.0"])
  end
end
