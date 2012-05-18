source :rubygems

gem "activesupport", ">= 2.3.6"
gem "tlsmail" if RUBY_VERSION <= '1.8.6'
gem "mime-types", "~> 1.16"
gem "treetop", "~> 1.4.10"
gem "i18n", ">= 0.4.0"

if defined?(RUBY_ENGINE) && RUBY_ENGINE == 'jruby'
  gem 'jruby-openssl'
end

group :test do
  gem "rake",       "> 0.8.7"
  gem "rspec",      "~> 2.8.0"
  case
  when defined?(RUBY_ENGINE) && RUBY_ENGINE == 'rbx'
    # Skip it
  when RUBY_PLATFORM == 'java'
    # Skip it
  when RUBY_VERSION < '1.9'
    gem "ruby-debug"
  else
    # Skip it
  end
end
