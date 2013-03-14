# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = "eventmachine"
  s.version = "0.12.10"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Francis Cianfrocca"]
  s.date = "2009-10-25"
  s.description = "EventMachine implements a fast, single-threaded engine for arbitrary network\ncommunications. It's extremely easy to use in Ruby. EventMachine wraps all\ninteractions with IP sockets, allowing programs to concentrate on the\nimplementation of network protocols. It can be used to create both network\nservers and clients. To create a server or client, a Ruby program only needs\nto specify the IP address and port, and provide a Module that implements the\ncommunications protocol. Implementations of several standard network protocols\nare provided with the package, primarily to serve as examples. The real goal\nof EventMachine is to enable programs to easily interface with other programs\nusing TCP/IP, especially if custom protocols are required.\n"
  s.email = "garbagecat10@gmail.com"
  s.extensions = ["ext/extconf.rb", "ext/fastfilereader/extconf.rb"]
  s.files = ["ext/extconf.rb", "ext/fastfilereader/extconf.rb"]
  s.homepage = "http://rubyeventmachine.com"
  s.rdoc_options = ["--title", "EventMachine", "--main", "README", "--line-numbers", "-x", "lib/em/version", "-x", "lib/emva", "-x", "lib/evma/", "-x", "lib/pr_eventmachine", "-x", "lib/jeventmachine"]
  s.require_paths = ["lib"]
  s.rubyforge_project = "eventmachine"
  s.rubygems_version = "1.8.21"
  s.summary = "Ruby/EventMachine library"

  if s.respond_to? :specification_version then
    s.specification_version = 3

    if Gem::Version.new(Gem::VERSION) >= Gem::Version.new('1.2.0') then
    else
    end
  else
  end
end
