require 'test_helper'

class DeprecatedSanitizerTest < ActiveSupport::TestCase
  def sanitize_helper
    Class.new do
      include ActionView::Helpers::SanitizeHelper
    end
  end

  test 'Action View sanitizer vendor is set to deprecated sanitizer' do
    assert_equal Rails::DeprecatedSanitizer, sanitize_helper.sanitizer_vendor
  end

  test 'Action View sanitizer vendor returns constant from HTML module' do
    assert_equal HTML::LinkSanitizer, sanitize_helper.sanitizer_vendor.link_sanitizer
  end

  test 'setting allowed tags modifies HTML::WhiteListSanitizers allowed tags' do
    sanitize_helper.sanitized_allowed_tags = %w(horse)
    assert_includes HTML::WhiteListSanitizer.allowed_tags, 'horse'
  end

  test 'setting allowed attributes modifies HTML::WhiteListSanitizers allowed attributes' do
    attrs = %w(for your health)
    sanitize_helper.sanitized_allowed_attributes = attrs
    attrs.each do |attr|
      assert_includes HTML::WhiteListSanitizer.allowed_attributes, attr
    end
  end
end
