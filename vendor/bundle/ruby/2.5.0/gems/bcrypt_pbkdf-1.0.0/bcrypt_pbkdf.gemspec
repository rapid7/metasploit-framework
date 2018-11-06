Gem::Specification.new do |s|
  s.name = 'bcrypt_pbkdf'
  s.version = '1.0.0'

  s.summary = "OpenBSD's bcrypt_pdkfd (a variant of PBKDF2 with bcrypt-based PRF)"
  s.description = <<-EOF
    This gem implements bcrypt_pdkfd (a variant of PBKDF2 with bcrypt-based PRF)
  EOF

  s.files = `git ls-files`.split("\n")
  s.require_path = 'lib'

  s.add_development_dependency 'rake-compiler', '~> 0.9.7'
  s.add_development_dependency 'minitest', '>= 5'
  s.add_development_dependency 'rbnacl', '~> 3.3'
  s.add_development_dependency 'rbnacl-libsodium', '~> 1.0.8'
  s.add_development_dependency 'rdoc', '~> 3.12'
  s.add_development_dependency 'rake-compiler-dock', '~> 0.5.3'

  s.has_rdoc = true
  s.rdoc_options += ['--title', 'bcrypt_pbkdf', '--line-numbers', '--inline-source', '--main', 'README.md']
  s.extra_rdoc_files += ['README.md', 'COPYING', 'CHANGELOG.md', *Dir['lib/**/*.rb']]

  s.extensions = 'ext/mri/extconf.rb'

  s.authors = ["Miklos Fazekas"]
  s.email = "mfazekas@szemafor.com"
  s.homepage = "https://github.com/net-ssh/bcrypt_pbkdf-ruby"
  s.license = "MIT"
end
