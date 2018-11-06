lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'dnsruby/version'

SPEC = Gem::Specification.new do |s|
  s.name = "dnsruby"
  s.version = Dnsruby::VERSION
  s.authors = ["Alex Dalitz"]
  s.email = 'alex@caerkettontech.com'
  s.homepage = "https://github.com/alexdalitz/dnsruby"
  s.platform = Gem::Platform::RUBY
  s.summary = "Ruby DNS(SEC) implementation"
  s.description = \
'Dnsruby is a pure Ruby DNS client library which implements a
stub resolver. It aims to comply with all DNS RFCs, including
DNSSEC NSEC3 support.'
  s.license = "Apache License, Version 2.0"
  s.files = `git ls-files -z`.split("\x0")

  s.post_install_message = \
"Installing dnsruby...
  For issues and source code: https://github.com/alexdalitz/dnsruby
  For general discussion (please tell us how you use dnsruby): https://groups.google.com/forum/#!forum/dnsruby"

  s.test_file = "test/ts_offline.rb"
  s.has_rdoc = true
  s.extra_rdoc_files = ["DNSSEC", "EXAMPLES", "README.md", "EVENTMACHINE"]

  unless /java/ === RUBY_PLATFORM
    s.add_development_dependency 'pry', '~> 0.10'
    s.add_development_dependency 'pry-byebug', '~> 2.0' if RUBY_VERSION >= '2'
  end

  s.add_development_dependency 'rake', '~> 10', '>= 10.3.2'
  s.add_development_dependency 'minitest', '~> 5.4'
  s.add_development_dependency 'rubydns', '~> 1.0'
  s.add_development_dependency 'nio4r', '~> 1.1'
  s.add_development_dependency 'minitest-display', '>= 0.3.0'

  if RUBY_VERSION >= "1.9.3"
    s.add_development_dependency 'coveralls', '~> 0.7'
  end

  s.add_runtime_dependency 'addressable', '~> 2.5'
end

