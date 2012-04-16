require 'contest'
require 'tilt'

begin
  require 'bluecloth'

  class BlueClothTemplateTest < Test::Unit::TestCase
    test "registered for '.md' files" do
      assert Tilt.mappings['md'].include?(Tilt::BlueClothTemplate)
    end

    test "registered for '.mkd' files" do
      assert Tilt.mappings['mkd'].include?(Tilt::BlueClothTemplate)
    end

    test "registered for '.markdown' files" do
      assert Tilt.mappings['markdown'].include?(Tilt::BlueClothTemplate)
    end

    test "preparing and evaluating templates on #render" do
      template = Tilt::BlueClothTemplate.new { |t| "# Hello World!" }
      assert_equal "<h1>Hello World!</h1>", template.render
    end

    test "can be rendered more than once" do
      template = Tilt::BlueClothTemplate.new { |t| "# Hello World!" }
      3.times { assert_equal "<h1>Hello World!</h1>", template.render }
    end

    test "smartypants when :smart is set" do
      template = Tilt::BlueClothTemplate.new(:smartypants => true) { |t|
        "OKAY -- 'Smarty Pants'" }
      assert_equal "<p>OKAY &mdash; &lsquo;Smarty Pants&rsquo;</p>",
        template.render
    end

    test "stripping HTML when :filter_html is set" do
      template = Tilt::BlueClothTemplate.new(:escape_html => true) { |t|
        "HELLO <blink>WORLD</blink>" }
      assert_equal "<p>HELLO &lt;blink>WORLD&lt;/blink></p>", template.render
    end
  end
rescue LoadError => boom
  warn "Tilt::BlueClothTemplate (disabled)\n"
end
