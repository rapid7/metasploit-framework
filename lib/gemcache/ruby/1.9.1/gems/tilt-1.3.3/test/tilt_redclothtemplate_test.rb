require 'contest'
require 'tilt'

begin
  require 'redcloth'

  class RedClothTemplateTest < Test::Unit::TestCase
    test "is registered for '.textile' files" do
      assert_equal Tilt::RedClothTemplate, Tilt['test.textile']
    end

    test "compiles and evaluates the template on #render" do
      template = Tilt::RedClothTemplate.new { |t| "h1. Hello World!" }
      assert_equal "<h1>Hello World!</h1>", template.render
    end

    test "can be rendered more than once" do
      template = Tilt::RedClothTemplate.new { |t| "h1. Hello World!" }
      3.times { assert_equal "<h1>Hello World!</h1>", template.render }
    end
  end
rescue LoadError => boom
  warn "Tilt::RedClothTemplate (disabled)\n"
end
