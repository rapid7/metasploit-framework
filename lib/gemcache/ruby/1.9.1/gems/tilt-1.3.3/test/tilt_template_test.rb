require 'contest'
require 'tilt'

class TiltTemplateTest < Test::Unit::TestCase

  class MockTemplate < Tilt::Template
    def prepare
    end
  end

  test "needs a file or block" do
    assert_raise(ArgumentError) { Tilt::Template.new }
  end

  test "initializing with a file" do
    inst = MockTemplate.new('foo.erb') {}
    assert_equal 'foo.erb', inst.file
  end

  test "initializing with a file and line" do
    inst = MockTemplate.new('foo.erb', 55) {}
    assert_equal 'foo.erb', inst.file
    assert_equal 55, inst.line
  end

  test "uses correct eval_file" do
    inst = MockTemplate.new('foo.erb', 55) {}
    assert_equal 'foo.erb', inst.eval_file
  end

  test "uses a default filename for #eval_file when no file provided" do
    inst = MockTemplate.new { 'Hi' }
    assert_not_nil inst.eval_file
    assert !inst.eval_file.include?("\n")
  end

  test "calculating template's #basename" do
    inst = MockTemplate.new('/tmp/templates/foo.html.erb') {}
    assert_equal 'foo.html.erb', inst.basename
  end

  test "calculating the template's #name" do
    inst = MockTemplate.new('/tmp/templates/foo.html.erb') {}
    assert_equal 'foo', inst.name
  end

  test "initializing with a data loading block" do
    MockTemplate.new { |template| "Hello World!" }
  end

  class InitializingMockTemplate < Tilt::Template
    @@initialized_count = 0
    def self.initialized_count
      @@initialized_count
    end

    def initialize_engine
      @@initialized_count += 1
    end

    def prepare
    end
  end

  test "one-time template engine initialization" do
    assert_nil InitializingMockTemplate.engine_initialized
    assert_equal 0, InitializingMockTemplate.initialized_count

    InitializingMockTemplate.new { "Hello World!" }
    assert InitializingMockTemplate.engine_initialized
    assert_equal 1, InitializingMockTemplate.initialized_count

    InitializingMockTemplate.new { "Hello World!" }
    assert_equal 1, InitializingMockTemplate.initialized_count
  end

  class PreparingMockTemplate < Tilt::Template
    include Test::Unit::Assertions
    def prepare
      assert !data.nil?
      @prepared = true
    end
    def prepared? ; @prepared ; end
  end

  test "raises NotImplementedError when #prepare not defined" do
    assert_raise(NotImplementedError) { Tilt::Template.new { |template| "Hello World!" } }
  end

  test "raises NotImplementedError when #evaluate or #template_source not defined" do
    inst = PreparingMockTemplate.new { |t| "Hello World!" }
    assert_raise(NotImplementedError) { inst.render }
    assert inst.prepared?
  end

  class SimpleMockTemplate < PreparingMockTemplate
    include Test::Unit::Assertions
    def evaluate(scope, locals, &block)
      assert prepared?
      assert !scope.nil?
      assert !locals.nil?
      "<em>#{@data}</em>"
    end
  end

  test "prepares and evaluates the template on #render" do
    inst = SimpleMockTemplate.new { |t| "Hello World!" }
    assert_equal "<em>Hello World!</em>", inst.render
    assert inst.prepared?
  end

  class SourceGeneratingMockTemplate < PreparingMockTemplate
    def precompiled_template(locals)
      "foo = [] ; foo << %Q{#{data}} ; foo.join"
    end
  end

  test "template_source with locals" do
    inst = SourceGeneratingMockTemplate.new { |t| 'Hey #{name}!' }
    assert_equal "Hey Joe!", inst.render(Object.new, :name => 'Joe')
    assert inst.prepared?
  end

  test "template_source with locals of strings" do
    inst = SourceGeneratingMockTemplate.new { |t| 'Hey #{name}!' }
    assert_equal "Hey Joe!", inst.render(Object.new, 'name' => 'Joe')
    assert inst.prepared?
  end

  class Person
    CONSTANT = "Bob"

    attr_accessor :name
    def initialize(name)
      @name = name
    end
  end

  test "template_source with an object scope" do
    inst = SourceGeneratingMockTemplate.new { |t| 'Hey #{@name}!' }
    scope = Person.new('Joe')
    assert_equal "Hey Joe!", inst.render(scope)
  end

  test "template_source with a block for yield" do
    inst = SourceGeneratingMockTemplate.new { |t| 'Hey #{yield}!' }
    assert_equal "Hey Joe!", inst.render(Object.new){ 'Joe' }
  end

  test "template which accesses a constant" do
    inst = SourceGeneratingMockTemplate.new { |t| 'Hey #{CONSTANT}!' }
    assert_equal "Hey Bob!", inst.render(Person.new("Joe"))
  end
end
