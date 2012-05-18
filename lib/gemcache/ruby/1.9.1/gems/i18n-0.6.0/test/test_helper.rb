$KCODE = 'u' if RUBY_VERSION <= '1.9'

require 'rubygems'
require 'test/unit'

# Do not load the i18n gem from libraries like active_support.
#
# This is required for testing against Rails 2.3 because active_support/vendor.rb#24 tries
# to load I18n using the gem method. Instead, we want to test the local library of course.
alias :gem_for_ruby_19 :gem # for 1.9. gives a super ugly seg fault otherwise
def gem(gem_name, *version_requirements)
  gem_name =='i18n' ? puts("skipping loading the i18n gem ...") : super
end

require 'bundler/setup'
require 'i18n'
require 'mocha'
require 'test_declarative'

class Test::Unit::TestCase
  def teardown
    I18n.locale = nil
    I18n.default_locale = :en
    I18n.load_path = []
    I18n.available_locales = nil
    I18n.backend = nil
  end

  def translations
    I18n.backend.instance_variable_get(:@translations)
  end

  def store_translations(*args)
    data   = args.pop
    locale = args.pop || :en
    I18n.backend.store_translations(locale, data)
  end

  def locales_dir
    File.dirname(__FILE__) + '/test_data/locales'
  end
end

module Kernel
  def setup_rufus_tokyo
    require 'rufus/tokyo'
  rescue LoadError => e
    puts "can't use KeyValue backend because: #{e.message}"
  end
end

Object.class_eval do
  def meta_class
    class << self; self; end
  end
end unless Object.method_defined?(:meta_class)
