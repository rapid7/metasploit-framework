# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "mime-types"
  s.version = "1.18"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Austin Ziegler"]
  s.date = "2012-03-21"
  s.description = "This library allows for the identification of a file's likely MIME content\ntype. This is release 1.17.2. The identification of MIME content type is based\non a file's filename extensions.\n\nMIME::Types for Ruby originally based on and synchronized with MIME::Types for\nPerl by Mark Overmeer, copyright 2001 - 2009. As of version 1.15, the data\nformat for the MIME::Type list has changed and the synchronization will no\nlonger happen.\n\n:include: Licence.rdoc"
  s.email = ["austin@rubyforge.org"]
  s.extra_rdoc_files = ["History.rdoc", "Licence.rdoc", "Manifest.txt", "README.rdoc", "type-lists/application.txt", "type-lists/audio.txt", "type-lists/image.txt", "type-lists/message.txt", "type-lists/model.txt", "type-lists/multipart.txt", "type-lists/text.txt", "type-lists/video.txt"]
  s.files = ["History.rdoc", "Licence.rdoc", "Manifest.txt", "README.rdoc", "type-lists/application.txt", "type-lists/audio.txt", "type-lists/image.txt", "type-lists/message.txt", "type-lists/model.txt", "type-lists/multipart.txt", "type-lists/text.txt", "type-lists/video.txt"]
  s.homepage = "http://mime-types.rubyforge.org/"
  s.rdoc_options = ["--main", "README.rdoc"]
  s.require_paths = ["lib"]
  s.rubyforge_project = "mime-types"
  s.rubygems_version = "1.8.21"
  s.summary = "This library allows for the identification of a file's likely MIME content type"

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_development_dependency(%q<rubyforge>, [">= 2.0.4"])
      s.add_development_dependency(%q<minitest>, ["~> 2.11"])
      s.add_development_dependency(%q<rdoc>, ["~> 3.10"])
      s.add_development_dependency(%q<nokogiri>, ["~> 1.5"])
      s.add_development_dependency(%q<hoe-doofus>, ["~> 1.0"])
      s.add_development_dependency(%q<hoe-gemspec>, ["~> 1.0"])
      s.add_development_dependency(%q<hoe-git>, ["~> 1.0"])
      s.add_development_dependency(%q<hoe-seattlerb>, ["~> 1.0"])
      s.add_development_dependency(%q<hoe>, ["~> 3.0"])
    else
      s.add_dependency(%q<rubyforge>, [">= 2.0.4"])
      s.add_dependency(%q<minitest>, ["~> 2.11"])
      s.add_dependency(%q<rdoc>, ["~> 3.10"])
      s.add_dependency(%q<nokogiri>, ["~> 1.5"])
      s.add_dependency(%q<hoe-doofus>, ["~> 1.0"])
      s.add_dependency(%q<hoe-gemspec>, ["~> 1.0"])
      s.add_dependency(%q<hoe-git>, ["~> 1.0"])
      s.add_dependency(%q<hoe-seattlerb>, ["~> 1.0"])
      s.add_dependency(%q<hoe>, ["~> 3.0"])
    end
  else
    s.add_dependency(%q<rubyforge>, [">= 2.0.4"])
    s.add_dependency(%q<minitest>, ["~> 2.11"])
    s.add_dependency(%q<rdoc>, ["~> 3.10"])
    s.add_dependency(%q<nokogiri>, ["~> 1.5"])
    s.add_dependency(%q<hoe-doofus>, ["~> 1.0"])
    s.add_dependency(%q<hoe-gemspec>, ["~> 1.0"])
    s.add_dependency(%q<hoe-git>, ["~> 1.0"])
    s.add_dependency(%q<hoe-seattlerb>, ["~> 1.0"])
    s.add_dependency(%q<hoe>, ["~> 3.0"])
  end
end
