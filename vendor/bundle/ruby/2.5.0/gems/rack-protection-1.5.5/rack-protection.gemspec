# Run `rake rack-protection.gemspec` to update the gemspec.
Gem::Specification.new do |s|
  # general infos
  s.name        = "rack-protection"
  s.version     = "1.5.5"
  s.description = "You should use protection!"
  s.homepage    = "http://github.com/rkh/rack-protection"
  s.summary     = s.description
  s.license     = 'MIT'

  # generated from git shortlog -sn
  s.authors = [
    "Konstantin Haase",
    "Alex Rodionov",
    "Patrick Ellis",
    "Jason Staten",
    "ITO Nobuaki",
    "Jeff Welling",
    "Matteo Centenaro",
    "Egor Homakov",
    "Florian Gilcher",
    "Fojas",
    "Igor Bochkariov",
    "Mael Clerambault",
    "Martin Mauch",
    "Renne Nissinen",
    "SAKAI, Kazuaki",
    "Stanislav Savulchik",
    "Steve Agalloco",
    "TOBY",
    "Thais Camilo and Konstantin Haase",
    "Vipul A M",
    "Akzhan Abdulin",
    "brookemckim",
    "Bj\u{f8}rge N\u{e6}ss",
    "Chris Heald",
    "Chris Mytton",
    "Corey Ward",
    "Dario Cravero",
    "David Kellum"
  ]

  # generated from git shortlog -sne
  s.email = [
    "konstantin.mailinglists@googlemail.com",
    "p0deje@gmail.com",
    "jstaten07@gmail.com",
    "patrick@soundcloud.com",
    "jeff.welling@gmail.com",
    "bugant@gmail.com",
    "daydream.trippers@gmail.com",
    "florian.gilcher@asquera.de",
    "developer@fojasaur.us",
    "ujifgc@gmail.com",
    "mael@clerambault.fr",
    "martin.mauch@gmail.com",
    "rennex@iki.fi",
    "kaz.july.7@gmail.com",
    "s.savulchik@gmail.com",
    "steve.agalloco@gmail.com",
    "toby.net.info.mail+git@gmail.com",
    "dev+narwen+rkh@rkh.im",
    "vipulnsward@gmail.com",
    "akzhan.abdulin@gmail.com",
    "brooke@digitalocean.com",
    "bjoerge@bengler.no",
    "cheald@gmail.com",
    "self@hecticjeff.net",
    "coreyward@me.com",
    "dario@uxtemple.com",
    "dek-oss@gravitext.com",
    "homakov@gmail.com"
  ]

  # generated from git ls-files
  s.files = [
    "License",
    "README.md",
    "Rakefile",
    "lib/rack-protection.rb",
    "lib/rack/protection.rb",
    "lib/rack/protection/authenticity_token.rb",
    "lib/rack/protection/base.rb",
    "lib/rack/protection/escaped_params.rb",
    "lib/rack/protection/form_token.rb",
    "lib/rack/protection/frame_options.rb",
    "lib/rack/protection/http_origin.rb",
    "lib/rack/protection/ip_spoofing.rb",
    "lib/rack/protection/json_csrf.rb",
    "lib/rack/protection/path_traversal.rb",
    "lib/rack/protection/remote_referrer.rb",
    "lib/rack/protection/remote_token.rb",
    "lib/rack/protection/session_hijacking.rb",
    "lib/rack/protection/version.rb",
    "lib/rack/protection/xss_header.rb",
    "rack-protection.gemspec",
    "spec/authenticity_token_spec.rb",
    "spec/base_spec.rb",
    "spec/escaped_params_spec.rb",
    "spec/form_token_spec.rb",
    "spec/frame_options_spec.rb",
    "spec/http_origin_spec.rb",
    "spec/ip_spoofing_spec.rb",
    "spec/json_csrf_spec.rb",
    "spec/path_traversal_spec.rb",
    "spec/protection_spec.rb",
    "spec/remote_referrer_spec.rb",
    "spec/remote_token_spec.rb",
    "spec/session_hijacking_spec.rb",
    "spec/spec_helper.rb",
    "spec/xss_header_spec.rb"
  ]

  # dependencies
  s.add_dependency "rack"
  s.add_development_dependency "rack-test"
  s.add_development_dependency "rspec", "~> 2.0"
end
