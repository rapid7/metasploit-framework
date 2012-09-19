require 'contest'
require 'tilt'

begin
  require 'maruku'

  class MarukuTemplateTest < Test::Unit::TestCase
    test "registered for '.md' files" do
      assert Tilt.mappings['md'].include?(Tilt::MarukuTemplate)
    end

    test "registered for '.mkd' files" do
      assert Tilt.mappings['mkd'].include?(Tilt::MarukuTemplate)
    end

    test "registered for '.markdown' files" do
      assert Tilt.mappings['markdown'].include?(Tilt::MarukuTemplate)
    end

    test "registered below Kramdown" do
      %w[md mkd markdown].each do |ext|
        mappings = Tilt.mappings[ext]
        kram_idx = mappings.index(Tilt::KramdownTemplate)
        maru_idx = mappings.index(Tilt::MarukuTemplate)
        assert maru_idx > kram_idx,
          "#{maru_idx} should be higher than #{kram_idx}"
      end
    end

    test "preparing and evaluating templates on #render" do
      template = Tilt::MarukuTemplate.new { |t| "# Hello World!" }
      assert_equal "<h1 id='hello_world'>Hello World!</h1>", template.render
    end

    test "can be rendered more than once" do
      template = Tilt::MarukuTemplate.new { |t| "# Hello World!" }
      3.times { assert_equal "<h1 id='hello_world'>Hello World!</h1>", template.render }
    end

    test "removes HTML when :filter_html is set" do
      template = Tilt::MarukuTemplate.new(:filter_html => true) { |t|
        "HELLO <blink>WORLD</blink>" }
      assert_equal "<p>HELLO </p>", template.render
    end
  end
rescue LoadError => boom
  warn "Tilt::MarukuTemplate (disabled)\n"
end
