# frozen_string_literal: true
require File.dirname(__FILE__) + '/spec_helper'

RSpec.describe YARD::Templates::Engine.template(:default, :docstring) do
  before do
    Registry.clear
    YARD.parse_string <<-'eof'
      private
      # Comments
      # @abstract override this class
      # @author Test
      # @version 1.0
      # @see A
      # @see http://example.com Example
      class A < B
        # HI
        def method_missing(*args) end
        # @deprecated
        def a; end

        # constructor method!
        def initialize(test) end
      end

      class C < A; end

      class D
        # @private
        def initialize; end
      end
    eof
  end

  it "renders html format correctly" do
    html_equals(Registry.at('A').format(html_options), :class001)
  end

  it "renders text format correctly" do
    text_equals(Registry.at('A').format, :class001)
  end

  it "hides private constructors" do
    html_equals(Registry.at('D').format(html_options(:verifier => Verifier.new("!@private"))), :class002)
  end
end
