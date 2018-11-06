# encoding: UTF-8

libdir = File.join(File.dirname(__FILE__), 'lib')
$LOAD_PATH.unshift(libdir) unless $LOAD_PATH.include?(libdir)

require "rbreadline/version"

spec = Gem::Specification.new do |s|
  # basic information
  s.name        = "rb-readline"
  s.version     = RbReadline::RB_READLINE_VERSION
  s.platform    = Gem::Platform::RUBY

  # description and details
  s.summary     = 'Pure-Ruby Readline Implementation'
  s.description = "The readline library provides a pure Ruby implementation of the GNU readline C library, as well as the Readline extension that ships as part of the standard library."

  # project information
  s.homepage          = 'http://github.com/ConnorAtherton/rb-readline'
  s.licenses          = ['BSD']

  # author and contributors
  s.authors     = ['Park Heesob', 'Daniel Berger', 'Luis Lavena', 'Connor Atherton']
  s.email       = ['phasis@gmail.com', 'djberg96@gmail.com', 'luislavena@gmail.com', 'c.liam.atherton@gmail.com']

  # requirements
  s.required_ruby_version = ">= 1.8.6"
  s.required_rubygems_version = ">= 1.3.5"

  # development dependencies
  s.add_development_dependency 'rake'
  s.add_development_dependency "minitest", "~> 5.2"

  # components, files and paths
  s.files = Dir[
    "{bench,examples,lib,test}/**/*.rb",
    "README.md",
    "LICENSE",
    "CHANGES",
    "Rakefile",
    "rb-readline.gemspec",
    "setup.rb"
  ]

  s.require_path = 'lib'

  # documentation
  s.rdoc_options << '--main'  << 'README.md' << '--title' << 'Rb-Readline - Documentation'

  s.extra_rdoc_files = %w(README.md LICENSE CHANGES)
end
