# -*- encoding: utf-8 -*-
# stub: yard 0.9.16 ruby lib

Gem::Specification.new do |s|
  s.name = "yard".freeze
  s.version = "0.9.16"

  s.required_rubygems_version = Gem::Requirement.new(">= 0".freeze) if s.respond_to? :required_rubygems_version=
  s.metadata = { "yard.run" => "yri" } if s.respond_to? :metadata=
  s.require_paths = ["lib".freeze]
  s.authors = ["Loren Segal".freeze]
  s.date = "2018-08-11"
  s.description = "    YARD is a documentation generation tool for the Ruby programming language.\n    It enables the user to generate consistent, usable documentation that can be\n    exported to a number of formats very easily, and also supports extending for\n    custom Ruby constructs such as custom class level definitions.\n".freeze
  s.email = "lsegal@soen.ca".freeze
  s.executables = ["yard".freeze, "yardoc".freeze, "yri".freeze]
  s.files = ["bin/yard".freeze, "bin/yardoc".freeze, "bin/yri".freeze]
  s.homepage = "http://yardoc.org".freeze
  s.licenses = ["MIT".freeze]
  s.post_install_message = "--------------------------------------------------------------------------------\nAs of YARD v0.9.2:\n\nRubyGems \"--document=yri,yard\" hooks are now supported. You can auto-configure\nYARD to automatically build the yri index for installed gems by typing:\n\n    $ yard config --gem-install-yri\n\nSee `yard config --help` for more information on RubyGems install hooks.\n\nYou can also add the following to your .gemspec to have YARD document your gem\non install:\n\n    spec.metadata[\"yard.run\"] = \"yri\" # use \"yard\" to build full HTML docs.\n\n--------------------------------------------------------------------------------\n".freeze
  s.rubygems_version = "2.7.7".freeze
  s.summary = "Documentation tool for consistent and usable documentation in Ruby.".freeze

  s.installed_by_version = "2.7.7" if s.respond_to? :installed_by_version
end
