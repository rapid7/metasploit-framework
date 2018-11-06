source 'https://rubygems.org'

group :development, :test do
  # Prevent occasions where minitest is not bundled in packaged versions of ruby (see #3826)
  gem 'minitest', '~> 4.7.0'
  gem 'shoulda-context', '~> 1.1.6'

  # test-unit moved to its own gem in ruby 2.2
  platforms :ruby_22, :ruby_23 do
    gem 'test-unit'
  end

  platforms :ruby_20, :ruby_21, :ruby_22, :ruby_23 do
    gem 'coveralls', :require => false
  end
end

gem 'rake-compiler', '>= 0.6.0'
gem 'rubygems-tasks'

if Bundler.current_ruby.mri? || Bundler.current_ruby.mingw? || Bundler.current_ruby.x64_mingw?
  gem 'rake', '>= 0.9.2'
  gem 'git', '~> 1.3.0'
end
