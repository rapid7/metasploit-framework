lib = "sawyer"
lib_file = File.expand_path("../lib/#{lib}.rb", __FILE__)
File.read(lib_file) =~ /\bVERSION\s*=\s*["'](.+?)["']/
version = $1

Gem::Specification.new do |spec|
  spec.specification_version = 2 if spec.respond_to? :specification_version=
  spec.required_rubygems_version = Gem::Requirement.new(">= 1.3.5") if spec.respond_to? :required_rubygems_version=

  spec.name    = lib
  spec.version = version

  spec.summary = "Secret User Agent of HTTP"

  spec.authors  = ["Rick Olson", "Wynn Netherland"]
  spec.email    = 'technoweenie@gmail.com'
  spec.homepage = 'https://github.com/lostisland/sawyer'
  spec.licenses = ['MIT']

  spec.add_dependency 'faraday',      ['~> 0.8', '< 1.0']
  spec.add_dependency 'addressable', ['>= 2.3.5', '< 2.6']

  spec.files = %w(Gemfile LICENSE.md README.md Rakefile)
  spec.files << "#{lib}.gemspec"
  spec.files += Dir.glob("lib/**/*.rb")
  spec.files += Dir.glob("test/**/*.rb")
  spec.files += Dir.glob("script/*")

  dev_null    = File.exist?('/dev/null') ? '/dev/null' : 'NUL'
  git_files   = `git ls-files -z 2>#{dev_null}`
  spec.files &= git_files.split("\0") if $?.success?
end
