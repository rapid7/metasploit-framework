source "https://rubygems.org"

gemspec :path => '..'

gem "activerecord", "~>4.1.0"

unless ENV['CI'] || RUBY_PLATFORM =~ /java/
  gem 'byebug'
end
