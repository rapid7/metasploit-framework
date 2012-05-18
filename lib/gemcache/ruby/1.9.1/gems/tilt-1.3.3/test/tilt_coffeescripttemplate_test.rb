require 'contest'
require 'tilt'

begin
  require 'coffee_script'

  class CoffeeScriptTemplateTest < Test::Unit::TestCase
    test "is registered for '.coffee' files" do
      assert_equal Tilt::CoffeeScriptTemplate, Tilt['test.coffee']
    end

    test "compiles and evaluates the template on #render" do
      template = Tilt::CoffeeScriptTemplate.new { |t| "puts 'Hello, World!'\n" }
      assert_match "puts('Hello, World!');", template.render
    end

    test "can be rendered more than once" do
      template = Tilt::CoffeeScriptTemplate.new { |t| "puts 'Hello, World!'\n" }
      3.times { assert_match "puts('Hello, World!');", template.render }
    end

    test "disabling coffee-script wrapper" do
      str = "puts 'Hello, World!'\n"

      template = Tilt::CoffeeScriptTemplate.new(:bare => true) { str }
      assert_equal "puts('Hello, World!');", template.render

      template2 = Tilt::CoffeeScriptTemplate.new(:no_wrap => true) { str}
      assert_equal "puts('Hello, World!');", template.render
    end

    context "disabling coffee-script wrapper globally" do
      setup do
        @bare = Tilt::CoffeeScriptTemplate.default_bare
      end

      teardown do
        Tilt::CoffeeScriptTemplate.default_bare = @bare
      end

      test "no options" do
        template = Tilt::CoffeeScriptTemplate.new { |t| "puts 'Hello, World!'\n" }
        assert_match "puts('Hello, World!');", template.render
        assert_match "(function() {", template.render
      end

      test "overridden by :bare" do
        template = Tilt::CoffeeScriptTemplate.new(:bare => false) { "puts 'Hello, World!'\n" }
        assert_not_equal "puts('Hello, World!');", template.render
      end

      test "overridden by :no_wrap" do
        template = Tilt::CoffeeScriptTemplate.new(:no_wrap => false) { "puts 'Hello, World!'\n" }
        assert_not_equal "puts('Hello, World!');", template.render
      end
    end
  end

rescue LoadError => boom
  warn "Tilt::CoffeeScriptTemplate (disabled)\n"
end
