# coding: utf-8

# During build, the Gemfile is temporarily moved and
# we must manually define the project root
if ENV['MSF_ROOT']
  lib = File.realpath(File.expand_path('lib', ENV['MSF_ROOT']))
else
  # have to use realpath as metasploit-framework is often loaded through a symlink and tools like Coverage and debuggers
  # require realpaths.
  lib = File.realpath(File.expand_path('../lib', __FILE__))
end

$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'metasploit/framework/version'

Gem::Specification.new do |spec|
  spec.name          = 'metasploit-framework-pcap'
  spec.version       = Metasploit::Framework::GEM_VERSION
  spec.authors       = ['Metasploit Hackers']
  spec.email         = ['metasploit-hackers@lists.sourceforge.net']
  spec.summary       = 'metasploit-framework packet capture dependencies'
  spec.description   = 'Gems needed to capture packets in metasploit-framework'
  spec.homepage      = 'https://www.metasploit.com'
  spec.license       = 'BSD-3-clause'

  # no files, just dependencies
  spec.files         = []

  # depend on metasploit-framewrok as the optional gems are useless with the actual code
  spec.add_runtime_dependency 'metasploit-framework', "= #{spec.version}"
  # get list of network interfaces, like eth* from OS.
  spec.add_runtime_dependency 'network_interface', '~> 0.0.1'
  # For sniffer and raw socket modules
  spec.add_runtime_dependency 'pcaprub'
end
