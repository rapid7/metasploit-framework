require 'contest'
require 'tilt'

begin
  require 'kramdown'

  class MarukuTemplateTest < Test::Unit::TestCase
    test "registered for '.md' files" do
      assert Tilt.mappings['md'].include?(Tilt::KramdownTemplate)
    end

    test "registered for '.mkd' files" do
      assert Tilt.mappings['mkd'].include?(Tilt::KramdownTemplate)
    end

    test "registered for '.markdown' files" do
      assert Tilt.mappings['markdown'].include?(Tilt::KramdownTemplate)
    end

    test "registered above MarukuTemplate" do
      %w[md mkd markdown].each do |ext|
        mappings = Tilt.mappings[ext]
        kram_idx = mappings.index(Tilt::KramdownTemplate)
        maru_idx = mappings.index(Tilt::MarukuTemplate)
        assert kram_idx < maru_idx,
          "#{kram_idx} should be lower than #{maru_idx}"
      end
    end

    test "preparing and evaluating templates on #render" do
      template = Tilt::KramdownTemplate.new { |t| "# Hello World!" }
      assert_equal "<h1 id='hello_world'>Hello World!</h1>", template.render
    end

    test "can be rendered more than once" do
      template = Tilt::KramdownTemplate.new { |t| "# Hello World!" }
      3.times { assert_equal "<h1 id='hello_world'>Hello World!</h1>", template.render }
    end
  end
rescue LoadError => boom
  warn "Tilt::KramdownTemplate (disabled)\n"
end
