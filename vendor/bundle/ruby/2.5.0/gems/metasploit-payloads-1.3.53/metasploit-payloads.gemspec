# -*- coding:binary -*-
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'metasploit-payloads/version'

Gem::Specification.new do |spec|
  spec.name          = 'metasploit-payloads'
  spec.version       = MetasploitPayloads::VERSION
  spec.authors       = ['OJ Reeves', 'Tod Beardsley', 'Chris Doughty', 'Brent Cook']
  spec.email         = ['oj@buffered.io', 'tod_beardsley@rapid7.com', 'chris_doughty@rapid7.com', 'brent_cook@rapid7.com']
  spec.description   = %q{Compiled binaries for Metasploit's Meterpreter}
  spec.summary       = %q{This gem contains the compiled binaries required to make
                        Meterpreter function, and eventually other payloads that
                        require compiled binaries.}
  spec.homepage      = 'http://www.metasploit.com'
  spec.license       = '3-clause (or "modified") BSD'

  spec.files         = `git ls-files`.split("\n")
  spec.files        += Dir['data/**/*']
  spec.executables   = []
  spec.require_paths = ['lib']

  spec.required_ruby_version = '>= 2.2.0'

  # NOTE: I had to comment out all the metadata sections because, for some reason,
  # my local installation of ruby/rake seems to think that metadata isn't valid.
  # I get the following error:
  #   C:\code\metasploit-payloads>rake win_prep
  #   rake aborted!
  #   There was a NoMethodError while loading metasploit-payloads.gemspec:
  #   undefined method `metadata' for #<Gem::Specification name=metasploit-payloads version=0.0.1> from
  #     C:/code/metasploit-payloads/metasploit-payloads.gemspec:29:in `block in <main>'
  #   C:/code/metasploit-payloads/Rakefile:1:in `<top (required)>'
  #   (See full trace by running task with --trace)

  # Since this is a pre-compiled binary, we'll need to give people a
  # hint as to what state the source was actually in when we compiled
  # up. In this way, the gem version can be linked to a commit hash and
  # users can get a sense of where in the history they are.
  #spec.metadata['source']              = 'https://github.com/rapid7/meterpreter'
  #spec.metadata['source_commit']       = '51b1a6d1dce9f617ab5fe0f27796e2217d9a9ca6'
  #spec.metadata['source_commit_url']   = "#{spec.metadata['source']}/commit/#{spec.metadata['source_commit']}"

  spec.add_development_dependency 'bundler', '~> 1.3'
  spec.add_development_dependency 'rake'
  spec.add_development_dependency 'gem-release'
end
