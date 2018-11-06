# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |spec|
  spec.name          = 'patch_finder'
  spec.version       = '1.0.2'
  spec.authors       = ['wchen-r7']
  spec.email         = ['wei_chen@rapid7.com']
  spec.summary       = 'Patch Finder'
  spec.description   = 'Generic Patch Finder'
  spec.homepage      = 'http://github.com/wchen-r7/patch-finder'
  spec.license       = 'BSD-3-clause'

  spec.files         = `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  spec.executables   = Dir.glob('bin/*').map{ |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_development_dependency "bundler", "~> 1.11"
  spec.add_development_dependency "rake", "~> 10.0"
  spec.add_development_dependency "rspec", "~> 3.0"
end
