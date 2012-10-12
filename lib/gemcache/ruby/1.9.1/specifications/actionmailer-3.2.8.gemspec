# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "actionmailer"
  s.version = "3.2.8"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["David Heinemeier Hansson"]
  s.date = "2012-08-09"
  s.description = "Email on Rails. Compose, deliver, receive, and test emails using the familiar controller/view pattern. First-class support for multipart email and attachments."
  s.email = "david@loudthinking.com"
  s.homepage = "http://www.rubyonrails.org"
  s.require_paths = ["lib"]
  s.required_ruby_version = Gem::Requirement.new(">= 1.8.7")
  s.requirements = ["none"]
  s.rubygems_version = "1.8.24"
  s.summary = "Email composition, delivery, and receiving framework (part of Rails)."

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
      s.add_runtime_dependency(%q<actionpack>, ["= 3.2.8"])
      s.add_runtime_dependency(%q<mail>, ["~> 2.4.4"])
    else
      s.add_dependency(%q<actionpack>, ["= 3.2.8"])
      s.add_dependency(%q<mail>, ["~> 2.4.4"])
    end
  else
    s.add_dependency(%q<actionpack>, ["= 3.2.8"])
    s.add_dependency(%q<mail>, ["~> 2.4.4"])
  end
end
