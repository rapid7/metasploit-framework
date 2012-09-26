require 'test_helper'

I18n::Tests.setup_rufus_tokyo

class I18nKeyValueApiTest < Test::Unit::TestCase
  include I18n::Tests::Basics
  include I18n::Tests::Defaults
  include I18n::Tests::Interpolation
  include I18n::Tests::Link
  include I18n::Tests::Lookup
  include I18n::Tests::Pluralization
  # include Tests::Api::Procs
  include I18n::Tests::Localization::Date
  include I18n::Tests::Localization::DateTime
  include I18n::Tests::Localization::Time
  # include Tests::Api::Localization::Procs

  STORE = Rufus::Tokyo::Cabinet.new('*')

  def setup
    I18n.backend = I18n::Backend::KeyValue.new(STORE)
    super
  end

  test "make sure we use the KeyValue backend" do
    assert_equal I18n::Backend::KeyValue, I18n.backend.class
  end
end if defined?(Rufus::Tokyo::Cabinet)
