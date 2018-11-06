# frozen_string_literal: true

RSpec.describe YARD::Parser::Ruby::TokenResolver do
  before(:all) do
    YARD.parse_string <<-eof
      module A
        def nomatch; end

        module B
          class C
            def initialize; end

            # @return [A::B::C]
            def self.foo; end

            # @return [self]
            def self.foo2; end

            def bar; end

            # @return [nil, D<String>]
            def baz; end

            # @return [nil]
            # @return [D<String>]
            def baz2; end

            # @overload qux(a)
            #   @return [nil]
            # @overload qux(b)
            #   @return [D<String>]
            def qux; end
          end

          class SubC < C
          end
        end
      end

      module D
        def baz; end
      end

      class Q
        def method; end

        # @return [Q]
        def self.q; end
      end
    eof
  end

  def tokens_match
    expect(@resolved.map {|t| t.first.last }.join).to eq @src
  end

  def objs_match(*objects)
    other_objs = @resolved.reject {|_, o| !o }.map {|_, o| o.path }
    expect(other_objs).to eq objects.flatten
    tokens_match
  end

  def tokenize(src, object = nil)
    @src = src
    @resolver = YARD::Parser::Ruby::TokenResolver.new(src, object)
    @resolved = @resolver.map {|t, o| [t[0, 2], o] }
  end

  it "returns regular tokens" do
    str = "def foo; Z::X::Y end"
    tokenize(str)
    tokens_match
  end

  it "resolves objects in compound constant paths" do
    tokenize "A::B::C"
    objs_match "A", "A::B", "A::B::C"
  end

  it "ignores full constant path if it breaks at beginning" do
    tokenize "E::A::B::C"
    objs_match []
  end

  it "ignores rest of constant path if sub-objects don't match" do
    tokenize "D::A::B::C"
    objs_match "D"
  end

  it "resets parsing at non-op tokens" do
    tokenize "A::B::C < Q"
    objs_match "A", "A::B", "A::B::C", "Q"
  end

  it "does not restart constant path" do
    tokenize "A::B::D::A"
    objs_match "A", "A::B"
  end

  it "resolves objects from base namespace" do
    tokenize "A::B::C C", Registry.at("A::B")
    objs_match "A", "A::B", "A::B::C", "A::B::C"
  end

  it "resolves methods" do
    tokenize "A::B::C.foo"
    objs_match "A", "A::B", "A::B::C", "A::B::C.foo"
  end

  it "supports 'new' constructor method" do
    tokenize "A::B::C.new"
    objs_match "A", "A::B", "A::B::C", "A::B::C#initialize"
  end

  it "skips constructor method if not found but continues resolving" do
    tokenize "Q.new.method"
    objs_match "Q", "Q#method"
  end

  it "resolves methods in inheritance tree" do
    tokenize "A::B::SubC.new"
    objs_match "A", "A::B", "A::B::SubC", "A::B::C#initialize"
  end

  it "parses compound method call chains based on return type" do
    tokenize "A::B::C.foo.baz"
    objs_match "A", "A::B", "A::B::C", "A::B::C.foo", "A::B::C#baz"
  end

  it "stops resolving if return types not found" do
    tokenize "A::B::C.foo.bar.baz.baz"
    objs_match "A", "A::B", "A::B::C", "A::B::C.foo", "A::B::C#bar"
  end

  it "handles multiple return types (returns first valid type match)" do
    tokenize "A::B::C.foo.baz.baz"
    objs_match "A", "A::B", "A::B::C", "A::B::C.foo", "A::B::C#baz", "D#baz"
  end

  it "doesn't perform lexical matching on methods" do
    tokenize "A::B::C.nomatch"
    objs_match "A", "A::B", "A::B::C"
  end

  it "handles multiple return tags (returns first valid type match)" do
    tokenize "A::B::C.foo.baz2.baz"
    objs_match "A", "A::B", "A::B::C", "A::B::C.foo", "A::B::C#baz2", "D#baz"
  end

  it "handles self as return type" do
    tokenize "A::B::C.foo2.baz"
    objs_match "A", "A::B", "A::B::C", "A::B::C.foo2", "A::B::C#baz"
  end

  it "handles multiple return tags inside overload tags" do
    tokenize "A::B::C.foo.qux.baz"
    objs_match "A", "A::B", "A::B::C", "A::B::C.foo", "A::B::C#qux", "D#baz"
  end

  it "resolves method calls with arguments" do
    tokenize "Q.q(A::B, A::B::C.foo().bar).q.q"
    objs_match "Q", "Q.q", "A", "A::B", "A", "A::B", "A::B::C",
               "A::B::C.foo", "A::B::C#bar", "Q.q", "Q.q"
  end
end if HAVE_RIPPER
