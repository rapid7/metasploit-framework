lib = File.expand_path('.', File.dirname(__FILE__))
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'metasm'

Gem::Specification.new do |s|
  s.name          = 'metasm'
  s.version       = '1.0.3'
  s.summary       =
    "Metasm is a cross-architecture assembler, disassembler, linker, and debugger."
  s.description   = ""
  s.authors       = ["Yoann Guillot"]
  s.email         = ['john at ofjj.net']
  s.files         = `git ls-files -z`.split("\x0")
  s.test_files    = s.files.grep(%r{^tests/})
  s.require_paths = ["."]
  s.homepage      = 'http://metasm.cr0.org'
  s.license       = 'LGPL'

  s.add_development_dependency "bundler", "~> 1.7"
  s.add_development_dependency "rake"
end

