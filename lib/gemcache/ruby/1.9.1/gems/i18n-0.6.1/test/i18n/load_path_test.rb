require 'test_helper'

class I18nLoadPathTest < Test::Unit::TestCase
  def setup
    I18n.locale = :en
    I18n.backend = I18n::Backend::Simple.new
    store_translations(:en, :foo => {:bar => 'bar', :baz => 'baz'})
  end

  test "nested load paths do not break locale loading" do
    I18n.load_path = [[locales_dir + '/en.yml']]
    assert_equal "baz", I18n.t(:'foo.bar')
  end

  test "loading an empty yml file raises an InvalidLocaleData exception" do
    assert_raise I18n::InvalidLocaleData do
      I18n.load_path = [[locales_dir + '/invalid/empty.yml']]
      I18n.t(:'foo.bar', :default => "baz")
    end
  end

  test "adding arrays of filenames to the load path does not break locale loading" do
    I18n.load_path << Dir[locales_dir + '/*.{rb,yml}']
    assert_equal "baz", I18n.t(:'foo.bar')
  end
end
