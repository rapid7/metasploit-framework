source "https://rubygems.org"

gemspec

group :development, :test do
  gem 'pry-byebug'

  # lock to 10.0 until rspec is upgraded
  gem 'rake', '~> 10.0'
end

group :test do
  gem 'rspec', '~> 2.11.0'
  gem 'rr',    '~> 1.0.4'
  gem 'sqlite3'
end
