require 'test_helper'

class TemplateTest < Test::Unit::TestCase
  include Liquid

  def test_tokenize_strings
    assert_equal [' '], Template.new.send(:tokenize, ' ')
    assert_equal ['hello world'], Template.new.send(:tokenize, 'hello world')
  end

  def test_tokenize_variables
    assert_equal ['{{funk}}'], Template.new.send(:tokenize, '{{funk}}')
    assert_equal [' ', '{{funk}}', ' '], Template.new.send(:tokenize, ' {{funk}} ')
    assert_equal [' ', '{{funk}}', ' ', '{{so}}', ' ', '{{brother}}', ' '], Template.new.send(:tokenize, ' {{funk}} {{so}} {{brother}} ')
    assert_equal [' ', '{{  funk  }}', ' '], Template.new.send(:tokenize, ' {{  funk  }} ')
  end

  def test_tokenize_blocks
    assert_equal ['{%comment%}'], Template.new.send(:tokenize, '{%comment%}')
    assert_equal [' ', '{%comment%}', ' '], Template.new.send(:tokenize, ' {%comment%} ')

    assert_equal [' ', '{%comment%}', ' ', '{%endcomment%}', ' '], Template.new.send(:tokenize, ' {%comment%} {%endcomment%} ')
    assert_equal ['  ', '{% comment %}', ' ', '{% endcomment %}', ' '], Template.new.send(:tokenize, "  {% comment %} {% endcomment %} ")
  end

  def test_instance_assigns_persist_on_same_template_object_between_parses
    t = Template.new
    assert_equal 'from instance assigns', t.parse("{% assign foo = 'from instance assigns' %}{{ foo }}").render
    assert_equal 'from instance assigns', t.parse("{{ foo }}").render
  end

  def test_instance_assigns_persist_on_same_template_parsing_between_renders
    t = Template.new.parse("{{ foo }}{% assign foo = 'foo' %}{{ foo }}")
    assert_equal 'foo', t.render
    assert_equal 'foofoo', t.render
  end

  def test_custom_assigns_do_not_persist_on_same_template
    t = Template.new
    assert_equal 'from custom assigns', t.parse("{{ foo }}").render('foo' => 'from custom assigns')
    assert_equal '', t.parse("{{ foo }}").render
  end

  def test_custom_assigns_squash_instance_assigns
    t = Template.new
    assert_equal 'from instance assigns', t.parse("{% assign foo = 'from instance assigns' %}{{ foo }}").render
    assert_equal 'from custom assigns', t.parse("{{ foo }}").render('foo' => 'from custom assigns')
  end

  def test_persistent_assigns_squash_instance_assigns
    t = Template.new
    assert_equal 'from instance assigns', t.parse("{% assign foo = 'from instance assigns' %}{{ foo }}").render
    t.assigns['foo'] = 'from persistent assigns'
    assert_equal 'from persistent assigns', t.parse("{{ foo }}").render
  end

  def test_lambda_is_called_once_from_persistent_assigns_over_multiple_parses_and_renders
    t = Template.new
    t.assigns['number'] = lambda { @global ||= 0; @global += 1 }
    assert_equal '1', t.parse("{{number}}").render
    assert_equal '1', t.parse("{{number}}").render
    assert_equal '1', t.render
    @global = nil
  end

  def test_lambda_is_called_once_from_custom_assigns_over_multiple_parses_and_renders
    t = Template.new
    assigns = {'number' => lambda { @global ||= 0; @global += 1 }}
    assert_equal '1', t.parse("{{number}}").render(assigns)
    assert_equal '1', t.parse("{{number}}").render(assigns)
    assert_equal '1', t.render(assigns)
    @global = nil
  end
end # TemplateTest
