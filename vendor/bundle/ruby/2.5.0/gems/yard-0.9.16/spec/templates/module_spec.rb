# frozen_string_literal: true
require File.dirname(__FILE__) + '/spec_helper'

RSpec.describe YARD::Templates::Engine.template(:default, :module) do
  before do
    Registry.clear
    YARD.parse_string <<-'eof'
      module B
        def c; end
        def d; end
        private
        def e; end
      end

      module BaseMod
        attr_reader :base_attr1
        attr_writer :base_attr2
        attr_accessor :base_attr3
      end

      # Comments
      module A
        include BaseMod
        attr_accessor :attr1
        attr_reader :attr2

        # @overload attr3
        #   @return [String] a string
        # @overload attr3=(value)
        #   @param [String] value sets the string
        #   @return [void]
        attr_accessor :attr3

        attr_writer :attr4

        def self.a; end
        def a; end
        alias b a

        # @overload test_overload(a)
        #   hello2
        #   @param [String] a hi
        def test_overload(*args) end

        # @overload test_multi_overload(a)
        # @overload test_multi_overload(a, b)
        def test_multi_overload(*args) end

        # @return [void]
        def void_meth; end

        include B

        class Y; end
        class Q; end
        class X; end
        module Z; end
        # A long docstring for the constant. With extra text
        # and newlines.
        CONSTANT = 'value'
        @@cvar = 'value' # @deprecated
      end

      module TMP; include A end
      class TMP2; extend A end
    eof
  end

  it "renders html format correctly" do
    html_equals(Registry.at('A').format(html_options(:hide_void_return => true,
      :verifier => Verifier.new('object.type != :method || object.visibility == :public'))),
        :module001)
  end

  it "renders text format correctly" do
    YARD.parse_string <<-'eof'
      module A
        include D, E, F, A::B::C
      end
    eof

    text_equals(Registry.at('A').format(text_options), :module001)
  end

  it "renders dot format correctly" do
    expect(Registry.at('A').format(:format => :dot, :dependencies => true, :full => true)).to eq example_contents(:module001, 'dot')
  end

  it "renders groups correctly in html" do
    Registry.clear
    YARD.parse_string <<-'eof'
      module A
        # @group Foo
        attr_accessor :foo_attr
        def foo; end
        def self.bar; end

        # @group Bar
        def baz; end

        # @endgroup

        def self.baz; end
      end
    eof

    html_equals(Registry.at('A').format(html_options), :module002)
  end

  it "ignores overwritten/private attributes/constants from inherited list" do
    Registry.clear
    YARD.parse_string <<-'eof'
      module B
        attr_reader :foo
        attr_accessor :bar
        # @private
        attr_writer :baz
        FOO = 1
      end
      module A
        include B
        def foo; end
        attr_reader :bar
        FOO = 2
      end
    eof

    html_equals(Registry.at('A').
      format(html_options(:verifier => Verifier.new('!@private'))), :module003)
  end

  it "embeds mixins with :embed_mixins = ['Foo', 'Bar', 'Baz::A*']" do
    Registry.clear
    YARD.parse_string <<-'eof'
      class A
        # This method is in A
        def foo; end

        include Foo
        extend Bar
        include BarFooBar
        include Baz::XYZ
        include Baz::ABC
      end

      module BarFooBar
        def bar_foo_bar; end
      end

      module Foo
        def self.not_included; end

        # Docs for xyz
        def xyz; end
        # Docs for bar_attr
        attr_accessor :bar_attr
      end

      module Bar
        def self.not_included; end

        # @group Booya

        # Docs for baz in Booya group
        def baz; end
      end

      module Baz
        module XYZ
          # listed as inherited
          def baz_xyz; end
        end

        module ABC
          def baz_abc; end
        end
      end
    eof

    html_equals(Registry.at('A').format(html_options(:embed_mixins => ['Foo', 'Bar', 'Baz::A*'])), :module004)
  end

  it "renders constant groups correctly in html" do
    Registry.clear
    YARD.parse_string <<-'eof'
      module A
        # @group Foo
        FOO = 1

        # @deprecated
        BAR = 2

        # @group Bar
        BAZ = 3

        # @endgroup

        WORLD = 4
      end
    eof
    html_equals(Registry.at('A').format(html_options), :module005)
  end
end
