require 'test_helper'

class ContextDrop < Liquid::Drop
  def scopes
    @context.scopes.size
  end

  def scopes_as_array
    (1..@context.scopes.size).to_a
  end

  def loop_pos
    @context['forloop.index']
  end

  def before_method(method)
    return @context[method]
  end
end

class ProductDrop < Liquid::Drop

  class TextDrop < Liquid::Drop
    def array
      ['text1', 'text2']
    end

    def text
      'text1'
    end
  end

  class CatchallDrop < Liquid::Drop
    def before_method(method)
      return 'method: ' << method.to_s
    end
  end

  def texts
    TextDrop.new
  end

  def catchall
    CatchallDrop.new
  end

  def context
    ContextDrop.new
  end

  protected
    def callmenot
      "protected"
    end
end

class EnumerableDrop < Liquid::Drop

  def size
    3
  end

  def each
    yield 1
    yield 2
    yield 3
  end
end

class DropsTest < Test::Unit::TestCase
  include Liquid

  def test_product_drop

    assert_nothing_raised do
      tpl = Liquid::Template.parse( '  '  )
      tpl.render('product' => ProductDrop.new)
    end
  end

  def test_text_drop
    output = Liquid::Template.parse( ' {{ product.texts.text }} '  ).render('product' => ProductDrop.new)
    assert_equal ' text1 ', output

  end

  def test_unknown_method
    output = Liquid::Template.parse( ' {{ product.catchall.unknown }} '  ).render('product' => ProductDrop.new)
    assert_equal ' method: unknown ', output

  end

  def test_integer_argument_drop
    output = Liquid::Template.parse( ' {{ product.catchall[8] }} '  ).render('product' => ProductDrop.new)
    assert_equal ' method: 8 ', output
  end

  def test_text_array_drop
    output = Liquid::Template.parse( '{% for text in product.texts.array %} {{text}} {% endfor %}'  ).render('product' => ProductDrop.new)
    assert_equal ' text1  text2 ', output
  end

  def test_context_drop
    output = Liquid::Template.parse( ' {{ context.bar }} '  ).render('context' => ContextDrop.new, 'bar' => "carrot")
    assert_equal ' carrot ', output
  end

  def test_nested_context_drop
    output = Liquid::Template.parse( ' {{ product.context.foo }} '  ).render('product' => ProductDrop.new, 'foo' => "monkey")
    assert_equal ' monkey ', output
  end

  def test_protected
    output = Liquid::Template.parse( ' {{ product.callmenot }} '  ).render('product' => ProductDrop.new)
    assert_equal '  ', output
  end

  def test_scope
    assert_equal '1', Liquid::Template.parse( '{{ context.scopes }}'  ).render('context' => ContextDrop.new)
    assert_equal '2', Liquid::Template.parse( '{%for i in dummy%}{{ context.scopes }}{%endfor%}'  ).render('context' => ContextDrop.new, 'dummy' => [1])
    assert_equal '3', Liquid::Template.parse( '{%for i in dummy%}{%for i in dummy%}{{ context.scopes }}{%endfor%}{%endfor%}'  ).render('context' => ContextDrop.new, 'dummy' => [1])
  end

  def test_scope_though_proc
    assert_equal '1', Liquid::Template.parse( '{{ s }}'  ).render('context' => ContextDrop.new, 's' => Proc.new{|c| c['context.scopes'] })
    assert_equal '2', Liquid::Template.parse( '{%for i in dummy%}{{ s }}{%endfor%}'  ).render('context' => ContextDrop.new, 's' => Proc.new{|c| c['context.scopes'] }, 'dummy' => [1])
    assert_equal '3', Liquid::Template.parse( '{%for i in dummy%}{%for i in dummy%}{{ s }}{%endfor%}{%endfor%}'  ).render('context' => ContextDrop.new, 's' => Proc.new{|c| c['context.scopes'] }, 'dummy' => [1])
  end

  def test_scope_with_assigns
    assert_equal 'variable', Liquid::Template.parse( '{% assign a = "variable"%}{{a}}'  ).render('context' => ContextDrop.new)
    assert_equal 'variable', Liquid::Template.parse( '{% assign a = "variable"%}{%for i in dummy%}{{a}}{%endfor%}'  ).render('context' => ContextDrop.new, 'dummy' => [1])
    assert_equal 'test', Liquid::Template.parse( '{% assign header_gif = "test"%}{{header_gif}}'  ).render('context' => ContextDrop.new)
    assert_equal 'test', Liquid::Template.parse( "{% assign header_gif = 'test'%}{{header_gif}}"  ).render('context' => ContextDrop.new)
  end

  def test_scope_from_tags
    assert_equal '1', Liquid::Template.parse( '{% for i in context.scopes_as_array %}{{i}}{% endfor %}'  ).render('context' => ContextDrop.new, 'dummy' => [1])
    assert_equal '12', Liquid::Template.parse( '{%for a in dummy%}{% for i in context.scopes_as_array %}{{i}}{% endfor %}{% endfor %}'  ).render('context' => ContextDrop.new, 'dummy' => [1])
    assert_equal '123', Liquid::Template.parse( '{%for a in dummy%}{%for a in dummy%}{% for i in context.scopes_as_array %}{{i}}{% endfor %}{% endfor %}{% endfor %}'  ).render('context' => ContextDrop.new, 'dummy' => [1])
  end

  def test_access_context_from_drop
    assert_equal '123', Liquid::Template.parse( '{%for a in dummy%}{{ context.loop_pos }}{% endfor %}'  ).render('context' => ContextDrop.new, 'dummy' => [1,2,3])
  end

  def test_enumerable_drop
    assert_equal '123', Liquid::Template.parse( '{% for c in collection %}{{c}}{% endfor %}').render('collection' => EnumerableDrop.new)
  end

  def test_enumerable_drop_size
    assert_equal '3', Liquid::Template.parse( '{{collection.size}}').render('collection' => EnumerableDrop.new)
  end

  def test_empty_string_value_access
    assert_equal '', Liquid::Template.parse('{{ product[value] }}').render('product' => ProductDrop.new, 'value' => '')
  end

  def test_nil_value_access
    assert_equal '', Liquid::Template.parse('{{ product[value] }}').render('product' => ProductDrop.new, 'value' => nil)
  end
end # DropsTest
