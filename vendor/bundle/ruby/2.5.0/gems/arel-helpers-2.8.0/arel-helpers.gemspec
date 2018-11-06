$:.unshift File.join(File.dirname(__FILE__), 'lib')
require 'arel-helpers/version'

Gem::Specification.new do |s|
  s.name     = "arel-helpers"
  s.version  = ::ArelHelpers::VERSION
  s.authors  = ["Cameron Dutro"]
  s.email    = ["camertron@gmail.com"]
  s.homepage = "https://github.com/camertron/arel-helpers"
  s.license  = 'MIT'
  s.description = s.summary = "Useful tools to help construct database queries with ActiveRecord and Arel."

  s.platform = Gem::Platform::RUBY
  s.has_rdoc = true

  if ENV["AR"]
    s.add_dependency 'activerecord', ENV["AR"]
  else
    s.add_dependency 'activerecord', '>= 3.1.0', '< 6'
  end

  s.require_path = 'lib'
  s.files = Dir["{lib,spec}/**/*", "Gemfile", "History.txt", "README.md", "Rakefile", "arel-helpers.gemspec"]
end
