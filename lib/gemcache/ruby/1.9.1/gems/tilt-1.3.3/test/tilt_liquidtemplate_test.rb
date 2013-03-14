require 'contest'
require 'tilt'

begin
  require 'liquid'

  class LiquidTemplateTest < Test::Unit::TestCase
    test "registered for '.liquid' files" do
      assert_equal Tilt::LiquidTemplate, Tilt['test.liquid']
    end

    test "preparing and evaluating templates on #render" do
      template = Tilt::LiquidTemplate.new { |t| "Hello World!" }
      assert_equal "Hello World!", template.render
    end

    test "can be rendered more than once" do
      template = Tilt::LiquidTemplate.new { |t| "Hello World!" }
      3.times { assert_equal "Hello World!", template.render }
    end

    test "passing locals" do
      template = Tilt::LiquidTemplate.new { "Hey {{ name }}!" }
      assert_equal "Hey Joe!", template.render(nil, :name => 'Joe')
    end

    # Object's passed as "scope" to LiquidTemplate may respond to
    # #to_h with a Hash. The Hash's contents are merged underneath
    # Tilt locals.
    class ExampleLiquidScope
      def to_h
        { :beer => 'wet', :whisky => 'wetter' }
      end
    end

    test "combining scope and locals when scope responds to #to_h" do
      template =
        Tilt::LiquidTemplate.new {
          'Beer is {{ beer }} but Whisky is {{ whisky }}.'
        }
      scope = ExampleLiquidScope.new
      assert_equal "Beer is wet but Whisky is wetter.", template.render(scope)
    end

    test "precedence when locals and scope define same variables" do
      template =
        Tilt::LiquidTemplate.new {
          'Beer is {{ beer }} but Whisky is {{ whisky }}.'
        }
      scope = ExampleLiquidScope.new
      assert_equal "Beer is great but Whisky is greater.",
        template.render(scope, :beer => 'great', :whisky => 'greater')
    end

    # Object's passed as "scope" to LiquidTemplate that do not
    # respond to #to_h are silently ignored.
    class ExampleIgnoredLiquidScope
    end

    test "handling scopes that do not respond to #to_h" do
      template = Tilt::LiquidTemplate.new { 'Whisky' }
      scope = ExampleIgnoredLiquidScope.new
      assert_equal "Whisky", template.render(scope)
    end

    test "passing a block for yield" do
      template =
        Tilt::LiquidTemplate.new {
          'Beer is {{ yield }} but Whisky is {{ content }}ter.'
        }
      assert_equal "Beer is wet but Whisky is wetter.",
        template.render({}) { 'wet' }
    end
  end

rescue LoadError => boom
  warn "Tilt::LiquidTemplate (disabled)\n"
end
