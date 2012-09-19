require 'test_helper'

class I18nExceptionsTest < Test::Unit::TestCase
  def test_invalid_locale_stores_locale
    force_invalid_locale
  rescue I18n::ArgumentError => e
    assert_nil exception.locale
  end

  test "passing an invalid locale raises an InvalidLocale exception" do
    force_invalid_locale do |exception|
      assert_equal 'nil is not a valid locale', exception.message
    end
  end

  test "MissingTranslationData exception stores locale, key and options" do
    force_missing_translation_data do |exception|
      assert_equal 'de', exception.locale
      assert_equal :foo, exception.key
      assert_equal({:scope => :bar}, exception.options)
    end
  end

  test "MissingTranslationData message contains the locale and scoped key" do
    force_missing_translation_data do |exception|
      assert_equal 'translation missing: de.bar.foo', exception.message
    end
  end

  test "MissingTranslationData html_message is a span with the titlelized last key token" do
    force_missing_translation_data do |exception|
      assert_equal '<span class="translation_missing" title="translation missing: de.bar.foo">Foo</span>', exception.html_message
    end
  end

  test "ExceptionHandler returns the html_message if :rescue_format => :html was given" do
    message = force_missing_translation_data(:rescue_format => :html)
    assert_equal '<span class="translation_missing" title="translation missing: de.bar.foo">Foo</span>', message
  end

  test "InvalidPluralizationData stores entry and count" do
    force_invalid_pluralization_data do |exception|
      assert_equal [:bar], exception.entry
      assert_equal 1, exception.count
    end
  end

  test "InvalidPluralizationData message contains count and data" do
    force_invalid_pluralization_data do |exception|
      assert_equal 'translation data [:bar] can not be used with :count => 1', exception.message
    end
  end

  test "MissingInterpolationArgument stores key and string" do
    assert_raise(I18n::MissingInterpolationArgument) { force_missing_interpolation_argument }
    force_missing_interpolation_argument do |exception|
      # assert_equal :bar, exception.key
      assert_equal "%{bar}", exception.string
    end
  end

  test "MissingInterpolationArgument message contains the missing and given arguments" do
    force_missing_interpolation_argument do |exception|
      assert_equal 'missing interpolation argument in "%{bar}" ({:baz=>"baz"} given)', exception.message
    end
  end

  test "ReservedInterpolationKey stores key and string" do
    force_reserved_interpolation_key do |exception|
      assert_equal :scope, exception.key
      assert_equal "%{scope}", exception.string
    end
  end

  test "ReservedInterpolationKey message contains the reserved key" do
    force_reserved_interpolation_key do |exception|
      assert_equal 'reserved key :scope used in "%{scope}"', exception.message
    end
  end

  private

    def force_invalid_locale
      I18n.translate(:foo, :locale => nil)
    rescue I18n::ArgumentError => e
      block_given? ? yield(e) : raise(e)
    end

    def force_missing_translation_data(options = {})
      I18n.backend.store_translations('de', :bar => nil)
      I18n.translate(:foo, options.merge(:scope => :bar, :locale => :de))
    rescue I18n::ArgumentError => e
      block_given? ? yield(e) : raise(e)
    end

    def force_invalid_pluralization_data
      I18n.backend.store_translations('de', :foo => [:bar])
      I18n.translate(:foo, :count => 1, :locale => :de)
    rescue I18n::ArgumentError => e
      block_given? ? yield(e) : raise(e)
    end

    def force_missing_interpolation_argument
      I18n.backend.store_translations('de', :foo => "%{bar}")
      I18n.translate(:foo, :baz => 'baz', :locale => :de)
    rescue I18n::ArgumentError => e
      block_given? ? yield(e) : raise(e)
    end

    def force_reserved_interpolation_key
      I18n.backend.store_translations('de', :foo => "%{scope}")
      I18n.translate(:foo, :baz => 'baz', :locale => :de)
    rescue I18n::ArgumentError => e
      block_given? ? yield(e) : raise(e)
    end
end
