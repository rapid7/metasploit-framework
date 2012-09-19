require 'contest'
require 'tilt'

begin
  require 'creole'

  class CreoleTemplateTest < Test::Unit::TestCase
    test "is registered for '.creole' files" do
      assert_equal Tilt::CreoleTemplate, Tilt['test.creole']
    end

    test "registered for '.wiki' files" do
      assert Tilt.mappings['wiki'].include?(Tilt::CreoleTemplate)
    end

    test "compiles and evaluates the template on #render" do
      template = Tilt::CreoleTemplate.new { |t| "= Hello World!" }
      assert_equal "<h1>Hello World!</h1>", template.render
    end

    test "can be rendered more than once" do
      template = Tilt::CreoleTemplate.new { |t| "= Hello World!" }
      3.times { assert_equal "<h1>Hello World!</h1>", template.render }
    end
  end
rescue LoadError => boom
  warn "Tilt::CreoleTemplate (disabled)\n"
end
