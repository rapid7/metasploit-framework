# -*- encoding: utf-8 -*-

Gem::Specification.new do |gem|
  gem.name          = "fivemat"
  gem.version       = "1.3.7"
  gem.authors       = ["Tim Pope"]
  gem.email         = ["code@tp" + 'ope.net']
  gem.description   = %q{MiniTest/RSpec/Cucumber formatter that gives each test file its own line of dots}
  gem.summary       = %q{Why settle for a test output format when you could have a test output fivemat?}
  gem.homepage      = "https://github.com/tpope/fivemat"
  gem.license       = "MIT"

  gem.files         = `git ls-files`.split($\)
  gem.executables   = gem.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.require_paths = ["lib"]

  gem.add_development_dependency('rake')
end
