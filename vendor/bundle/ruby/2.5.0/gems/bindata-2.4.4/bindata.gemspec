$LOAD_PATH.unshift File.expand_path("../lib", __FILE__)
require 'bindata/version'

Gem::Specification.new do |s|
  s.name = 'bindata'
  s.version = BinData::VERSION
  s.platform = Gem::Platform::RUBY
  s.summary = 'A declarative way to read and write binary file formats'
  s.author = 'Dion Mendel'
  s.email = 'bindata@dm9.info'
  s.homepage = 'http://github.com/dmendel/bindata'
  s.rubyforge_project = 'bindata'
  s.require_path = 'lib'
  s.has_rdoc = true
  s.extra_rdoc_files = ['NEWS.rdoc']
  s.rdoc_options << '--main' << 'NEWS.rdoc'
  s.files = `git ls-files`.split("\n")
  s.license = 'Ruby'

  s.add_development_dependency('rake')
  s.add_development_dependency('minitest', "> 5.0.0")
  s.add_development_dependency('coveralls')
  s.description = <<-END.gsub(/^ +/, "")
    BinData is a declarative way to read and write binary file formats.

    This means the programmer specifies *what* the format of the binary
    data is, and BinData works out *how* to read and write data in this
    format.  It is an easier ( and more readable ) alternative to
    ruby's #pack and #unpack methods.
  END
end
