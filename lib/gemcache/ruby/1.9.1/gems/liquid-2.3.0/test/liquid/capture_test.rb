require 'test_helper'

class CaptureTest < Test::Unit::TestCase
  include Liquid

  def test_captures_block_content_in_variable
    assert_template_result("test string", "{% capture 'var' %}test string{% endcapture %}{{var}}", {})
  end

  def test_capture_to_variable_from_outer_scope_if_existing
    template_source = <<-END_TEMPLATE
    {% assign var = '' %}
    {% if true %}
    {% capture var %}first-block-string{% endcapture %}
    {% endif %}
    {% if true %}
    {% capture var %}test-string{% endcapture %}
    {% endif %}
    {{var}}
    END_TEMPLATE
    template = Template.parse(template_source)
    rendered = template.render
    assert_equal "test-string", rendered.gsub(/\s/, '')
  end

  def test_assigning_from_capture
    template_source = <<-END_TEMPLATE
    {% assign first = '' %}
    {% assign second = '' %}
    {% for number in (1..3) %}
    {% capture first %}{{number}}{% endcapture %}
    {% assign second = first %}
    {% endfor %}
    {{ first }}-{{ second }}
    END_TEMPLATE
    template = Template.parse(template_source)
    rendered = template.render
    assert_equal "3-3", rendered.gsub(/\s/, '')
  end
end # CaptureTest
