# frozen_string_literal: true
require File.expand_path('../lib/yard/version', __FILE__)

Gem::Specification.new do |s|
  s.name          = "yard"
  s.summary       = "Documentation tool for consistent and usable documentation in Ruby."
  s.description   = <<-eof
    YARD is a documentation generation tool for the Ruby programming language.
    It enables the user to generate consistent, usable documentation that can be
    exported to a number of formats very easily, and also supports extending for
    custom Ruby constructs such as custom class level definitions.
  eof
  s.version       = YARD::VERSION
  s.date          = Time.now.strftime('%Y-%m-%d')
  s.author        = "Loren Segal"
  s.email         = "lsegal@soen.ca"
  s.homepage      = "http://yardoc.org"
  s.platform      = Gem::Platform::RUBY
  s.files         = Dir.glob("{docs,bin,lib,spec,templates,benchmarks}/**/*") +
                    ['CHANGELOG.md', 'LICENSE', 'LEGAL', 'README.md', 'Rakefile', '.yardopts', __FILE__]
  s.require_paths = ['lib']
  s.executables   = ['yard', 'yardoc', 'yri']
  s.license = 'MIT' if s.respond_to?(:license=)
  s.metadata['yard.run'] = 'yri'
  s.post_install_message = <<-eof
--------------------------------------------------------------------------------
As of YARD v0.9.2:

RubyGems "--document=yri,yard" hooks are now supported. You can auto-configure
YARD to automatically build the yri index for installed gems by typing:

    $ yard config --gem-install-yri

See `yard config --help` for more information on RubyGems install hooks.

You can also add the following to your .gemspec to have YARD document your gem
on install:

    spec.metadata["yard.run"] = "yri" # use "yard" to build full HTML docs.

--------------------------------------------------------------------------------
eof
end
