# Why use bundler?
# Well, not all development dependencies install on all rubies. Moreover, `gem
# install sinatra --development` doesn't work, as it will also try to install
# development dependencies of our dependencies, and those are not conflict free.
# So, here we are, `bundle install`.
#
# If you have issues with a gem: `bundle install --without-coffee-script`.

RUBY_ENGINE = 'ruby' unless defined? RUBY_ENGINE
source 'https://rubygems.org' unless ENV['QUICK']
gemspec

gem 'rake', '~> 10.0'
gem 'rack-test', '>= 0.6.2'
gem "minitest", "~> 5.0"

if RUBY_ENGINE == 'jruby'
  gem 'nokogiri', '!= 1.5.0'
  gem 'jruby-openssl'
  gem 'trinidad'
end

if RUBY_VERSION < '1.9.3'
  gem 'activesupport', '~> 3.2'
  gem 'i18n', '~> 0.6.0'
else
  gem 'activesupport', '~> 4.2'
end

if RUBY_ENGINE == "ruby"
  if RUBY_VERSION > '1.9.2'
    gem 'less', '~> 2.0'
    gem 'therubyracer'
    gem 'redcarpet'
    gem 'wlang', '>= 2.0.1'
    gem 'bluecloth'
    gem 'rdiscount'
    gem 'RedCloth'
    gem 'puma'
    gem 'net-http-server'
    gem 'yajl-ruby'
    gem 'thin'
    gem 'slim', '~> 2.0'
    gem 'coffee-script', '>= 2.0'
    gem 'rdoc'
    gem 'kramdown'
    gem 'maruku'
    gem 'creole'
    gem 'wikicloth'
    gem 'markaby'
    gem 'radius'
    gem 'asciidoctor'
    gem 'liquid', '~> 3.0'
    gem 'stylus'
    gem 'rabl'
    gem 'builder'
    gem 'erubis'
    gem 'haml', '>= 3.0'
    gem 'sass'
    
    if RUBY_VERSION < '2.1.0'
      gem 'nokogiri', '~> 1.6.8'
    else
      gem 'nokogiri', '~> 1.7.0'
    end
  else
    gem 'nokogiri', '~> 1.5.11'
  end
end

if RUBY_ENGINE == "rbx"
  gem 'json'
  gem 'rubysl'
  gem 'rubysl-test-unit'
end

platforms :ruby_18, :jruby do
  gem 'json', '~> 1.8' unless RUBY_VERSION > '1.9' # is there a jruby but 1.8 only selector?
end
