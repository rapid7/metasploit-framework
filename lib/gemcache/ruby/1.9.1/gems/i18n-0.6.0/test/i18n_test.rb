require 'test_helper'

class I18nTest < Test::Unit::TestCase
  def setup
    I18n.backend.store_translations(:'en', :currency => { :format => { :separator => '.', :delimiter => ',', } })
  end

  test "exposes its VERSION constant" do
    assert I18n::VERSION
  end

  test "uses the simple backend by default" do
    assert I18n.backend.is_a?(I18n::Backend::Simple)
  end

  test "can set the backend" do
    begin
      assert_nothing_raised { I18n.backend = self }
      assert_equal self, I18n.backend
    ensure
      I18n.backend = I18n::Backend::Simple.new
    end
  end

  test "uses :en as a default_locale by default" do
    assert_equal :en, I18n.default_locale
  end

  test "can set the default locale" do
    begin
      assert_nothing_raised { I18n.default_locale = 'de' }
      assert_equal :de, I18n.default_locale
    ensure
      I18n.default_locale = :en
    end
  end

  test "uses the default locale as a locale by default" do
    assert_equal I18n.default_locale, I18n.locale
  end

  test "sets the current locale to Thread.current" do
    assert_nothing_raised { I18n.locale = 'de' }
    assert_equal :de, I18n.locale
    assert_equal :de, Thread.current[:i18n_config].locale
    I18n.locale = :en
  end

  test "can set the configuration object" do
    begin
      I18n.config = self
      assert_equal self, I18n.config
      assert_equal self, Thread.current[:i18n_config]
    ensure
      I18n.config = ::I18n::Config.new
    end
  end

  test "locale is not shared between configurations" do
    a = I18n::Config.new
    b = I18n::Config.new
    a.locale = :fr
    b.locale = :es
    assert_equal :fr, a.locale
    assert_equal :es, b.locale
    assert_equal :en, I18n.locale
  end

  test "other options are shared between configurations" do
    begin
      a = I18n::Config.new
      b = I18n::Config.new
      a.default_locale = :fr
      b.default_locale = :es
      assert_equal :es, a.default_locale
      assert_equal :es, b.default_locale
      assert_equal :es, I18n.default_locale
    ensure
      I18n.default_locale = :en
    end
  end

  test "uses a dot as a default_separator by default" do
    assert_equal '.', I18n.default_separator
  end

  test "can set the default_separator" do
    begin
      assert_nothing_raised { I18n.default_separator = "\001" }
    ensure
      I18n.default_separator = '.'
    end
  end

  test "normalize_keys normalizes given locale, keys and scope to an array of single-key symbols" do
    assert_equal [:en, :foo, :bar], I18n.normalize_keys(:en, :bar, :foo)
    assert_equal [:en, :foo, :bar, :baz, :buz], I18n.normalize_keys(:en, :'baz.buz', :'foo.bar')
    assert_equal [:en, :foo, :bar, :baz, :buz], I18n.normalize_keys(:en, 'baz.buz', 'foo.bar')
    assert_equal [:en, :foo, :bar, :baz, :buz], I18n.normalize_keys(:en, %w(baz buz), %w(foo bar))
    assert_equal [:en, :foo, :bar, :baz, :buz], I18n.normalize_keys(:en, [:baz, :buz], [:foo, :bar])
  end

  test "normalize_keys discards empty keys" do
    assert_equal [:en, :foo, :bar, :baz, :buz], I18n.normalize_keys(:en, :'baz..buz', :'foo..bar')
    assert_equal [:en, :foo, :bar, :baz, :buz], I18n.normalize_keys(:en, :'baz......buz', :'foo......bar')
    assert_equal [:en, :foo, :bar, :baz, :buz], I18n.normalize_keys(:en, ['baz', nil, '', 'buz'], ['foo', nil, '', 'bar'])
  end

  test "normalize_keys uses a given separator" do
    assert_equal [:en, :foo, :bar, :baz, :buz], I18n.normalize_keys(:en, :'baz|buz', :'foo|bar', '|')
  end

  test "can set the exception_handler" do
    begin
      previous_exception_handler = I18n.exception_handler
      assert_nothing_raised { I18n.exception_handler = :custom_exception_handler }
    ensure
      I18n.exception_handler = previous_exception_handler
    end
  end

  test "uses a custom exception handler set to I18n.exception_handler" do
    begin
      previous_exception_handler = I18n.exception_handler
      I18n.exception_handler = :custom_exception_handler
      I18n.expects(:custom_exception_handler)
      I18n.translate :bogus
    ensure
      I18n.exception_handler = previous_exception_handler
    end
  end

  test "uses a custom exception handler passed as an option" do
    I18n.expects(:custom_exception_handler)
    I18n.translate(:bogus, :exception_handler => :custom_exception_handler)
  end

  test "delegates translate calls to the backend" do
    I18n.backend.expects(:translate).with('de', :foo, {})
    I18n.translate :foo, :locale => 'de'
  end

  test "delegates localize calls to the backend" do
    I18n.backend.expects(:localize).with('de', :whatever, :default, {})
    I18n.localize :whatever, :locale => 'de'
  end

  test "translate given no locale uses the current locale" do
    I18n.backend.expects(:translate).with(:en, :foo, {})
    I18n.translate :foo
  end

  test "translate works with nested symbol keys" do
    assert_equal ".", I18n.t(:'currency.format.separator')
  end

  test "translate works with nested string keys" do
    assert_equal ".", I18n.t('currency.format.separator')
  end

  test "translate with an array as a scope works" do
    assert_equal ".", I18n.t(:separator, :scope => %w(currency format))
  end

  test "translate with an array containing dot separated strings as a scope works" do
    assert_equal ".", I18n.t(:separator, :scope => ['currency.format'])
  end

  test "translate with an array of keys and a dot separated string as a scope works" do
    assert_equal [".", ","], I18n.t(%w(separator delimiter), :scope => 'currency.format')
  end

  test "translate with an array of dot separated keys and a scope works" do
    assert_equal [".", ","], I18n.t(%w(format.separator format.delimiter), :scope => 'currency')
  end

  # def test_translate_given_no_args_raises_missing_translation_data
  #   assert_equal "translation missing: en, no key", I18n.t
  # end

  test "translate given a bogus key returns an error message" do
    assert_equal "translation missing: en.bogus", I18n.t(:bogus)
  end

  test "translate given an empty string as a key raises an I18n::ArgumentError" do
    assert_raise(I18n::ArgumentError) { I18n.t("") }
  end

  test "localize given nil raises an I18n::ArgumentError" do
    assert_raise(I18n::ArgumentError) { I18n.l nil }
  end

  test "localize givan an Object raises an I18n::ArgumentError" do
    assert_raise(I18n::ArgumentError) { I18n.l Object.new }
  end

  test "can use a lambda as an exception handler" do
    begin
      previous_exception_handler = I18n.exception_handler
      I18n.exception_handler = Proc.new { |exception, locale, key, options| key }
      assert_equal :test_proc_handler, I18n.translate(:test_proc_handler)
    ensure
      I18n.exception_handler = previous_exception_handler
    end
  end

  test "can use an object responding to #call as an exception handler" do
    begin
      previous_exception_handler = I18n.exception_handler
      I18n.exception_handler = Class.new do
        def call(exception, locale, key, options); key; end
      end.new
      assert_equal :test_proc_handler, I18n.translate(:test_proc_handler)
    ensure
      I18n.exception_handler = previous_exception_handler
    end
  end

  test "I18n.with_locale temporarily sets the given locale" do
    store_translations(:en, :foo => 'Foo in :en')
    store_translations(:de, :foo => 'Foo in :de')
    store_translations(:pl, :foo => 'Foo in :pl')

    I18n.with_locale      { assert_equal [:en, 'Foo in :en'], [I18n.locale, I18n.t(:foo)] }
    I18n.with_locale(:de) { assert_equal [:de, 'Foo in :de'], [I18n.locale, I18n.t(:foo)] }
    I18n.with_locale(:pl) { assert_equal [:pl, 'Foo in :pl'], [I18n.locale, I18n.t(:foo)] }
    I18n.with_locale(:en) { assert_equal [:en, 'Foo in :en'], [I18n.locale, I18n.t(:foo)] }

    assert_equal I18n.default_locale, I18n.locale
  end

  test "I18n.with_locale resets the locale in case of errors" do
    assert_raise(I18n::ArgumentError) { I18n.with_locale(:pl) { raise I18n::ArgumentError } }
    assert_equal I18n.default_locale, I18n.locale
  end
end
