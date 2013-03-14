require 'test_helper'

class VariableTest < Test::Unit::TestCase
  include Liquid

  def test_variable
    var = Variable.new('hello')
    assert_equal 'hello', var.name
  end

  def test_filters
    var = Variable.new('hello | textileze')
    assert_equal 'hello', var.name
    assert_equal [[:textileze,[]]], var.filters

    var = Variable.new('hello | textileze | paragraph')
    assert_equal 'hello', var.name
    assert_equal [[:textileze,[]], [:paragraph,[]]], var.filters

    var = Variable.new(%! hello | strftime: '%Y'!)
    assert_equal 'hello', var.name
    assert_equal [[:strftime,["'%Y'"]]], var.filters

    var = Variable.new(%! 'typo' | link_to: 'Typo', true !)
    assert_equal %!'typo'!, var.name
    assert_equal [[:link_to,["'Typo'", "true"]]], var.filters

    var = Variable.new(%! 'typo' | link_to: 'Typo', false !)
    assert_equal %!'typo'!, var.name
    assert_equal [[:link_to,["'Typo'", "false"]]], var.filters

    var = Variable.new(%! 'foo' | repeat: 3 !)
    assert_equal %!'foo'!, var.name
    assert_equal [[:repeat,["3"]]], var.filters

    var = Variable.new(%! 'foo' | repeat: 3, 3 !)
    assert_equal %!'foo'!, var.name
    assert_equal [[:repeat,["3","3"]]], var.filters

    var = Variable.new(%! 'foo' | repeat: 3, 3, 3 !)
    assert_equal %!'foo'!, var.name
    assert_equal [[:repeat,["3","3","3"]]], var.filters

    var = Variable.new(%! hello | strftime: '%Y, okay?'!)
    assert_equal 'hello', var.name
    assert_equal [[:strftime,["'%Y, okay?'"]]], var.filters

    var = Variable.new(%! hello | things: "%Y, okay?", 'the other one'!)
    assert_equal 'hello', var.name
    assert_equal [[:things,["\"%Y, okay?\"","'the other one'"]]], var.filters
  end

  def test_filter_with_date_parameter

    var = Variable.new(%! '2006-06-06' | date: "%m/%d/%Y"!)
    assert_equal "'2006-06-06'", var.name
    assert_equal [[:date,["\"%m/%d/%Y\""]]], var.filters

  end

  def test_filters_without_whitespace
    var = Variable.new('hello | textileze | paragraph')
    assert_equal 'hello', var.name
    assert_equal [[:textileze,[]], [:paragraph,[]]], var.filters

    var = Variable.new('hello|textileze|paragraph')
    assert_equal 'hello', var.name
    assert_equal [[:textileze,[]], [:paragraph,[]]], var.filters
  end

  def test_symbol
    var = Variable.new("http://disney.com/logo.gif | image: 'med' ")
    assert_equal 'http://disney.com/logo.gif', var.name
    assert_equal [[:image,["'med'"]]], var.filters
  end

  def test_string_single_quoted
    var = Variable.new(%| "hello" |)
    assert_equal '"hello"', var.name
  end

  def test_string_double_quoted
    var = Variable.new(%| 'hello' |)
    assert_equal "'hello'", var.name
  end

  def test_integer
    var = Variable.new(%| 1000 |)
    assert_equal "1000", var.name
  end

  def test_float
    var = Variable.new(%| 1000.01 |)
    assert_equal "1000.01", var.name
  end

  def test_string_with_special_chars
    var = Variable.new(%| 'hello! $!@.;"ddasd" ' |)
    assert_equal %|'hello! $!@.;"ddasd" '|, var.name
  end

  def test_string_dot
    var = Variable.new(%| test.test |)
    assert_equal 'test.test', var.name
  end
end


class VariableResolutionTest < Test::Unit::TestCase
  include Liquid

  def test_simple_variable
    template = Template.parse(%|{{test}}|)
    assert_equal 'worked', template.render('test' => 'worked')
    assert_equal 'worked wonderfully', template.render('test' => 'worked wonderfully')
  end

  def test_simple_with_whitespaces
    template = Template.parse(%|  {{ test }}  |)
    assert_equal '  worked  ', template.render('test' => 'worked')
    assert_equal '  worked wonderfully  ', template.render('test' => 'worked wonderfully')
  end

  def test_ignore_unknown
    template = Template.parse(%|{{ test }}|)
    assert_equal '', template.render
  end

  def test_hash_scoping
    template = Template.parse(%|{{ test.test }}|)
    assert_equal 'worked', template.render('test' => {'test' => 'worked'})
  end

  def test_preset_assigns
    template = Template.parse(%|{{ test }}|)
    template.assigns['test'] = 'worked'
    assert_equal 'worked', template.render
  end

  def test_reuse_parsed_template
    template = Template.parse(%|{{ greeting }} {{ name }}|)
    template.assigns['greeting'] = 'Goodbye'
    assert_equal 'Hello Tobi', template.render('greeting' => 'Hello', 'name' => 'Tobi')
    assert_equal 'Hello ', template.render('greeting' => 'Hello', 'unknown' => 'Tobi')
    assert_equal 'Hello Brian', template.render('greeting' => 'Hello', 'name' => 'Brian')
    assert_equal 'Goodbye Brian', template.render('name' => 'Brian')
    assert_equal({'greeting'=>'Goodbye'}, template.assigns)
  end

  def test_assigns_not_polluted_from_template
    template = Template.parse(%|{{ test }}{% assign test = 'bar' %}{{ test }}|)
    template.assigns['test'] = 'baz'
    assert_equal 'bazbar', template.render
    assert_equal 'bazbar', template.render
    assert_equal 'foobar', template.render('test' => 'foo')
    assert_equal 'bazbar', template.render
  end

  def test_hash_with_default_proc
    template = Template.parse(%|Hello {{ test }}|)
    assigns = Hash.new { |h,k| raise "Unknown variable '#{k}'" }
    assigns['test'] = 'Tobi'
    assert_equal 'Hello Tobi', template.render!(assigns)
    assigns.delete('test')
    e = assert_raises(RuntimeError) {
      template.render!(assigns)
    }
    assert_equal "Unknown variable 'test'", e.message
  end
end # VariableTest
