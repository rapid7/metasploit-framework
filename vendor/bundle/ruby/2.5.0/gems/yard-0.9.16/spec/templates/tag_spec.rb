# frozen_string_literal: true
require File.dirname(__FILE__) + '/spec_helper'

RSpec.describe YARD::Templates::Engine.template(:default, :tags) do
  before { Registry.clear }

  describe "all known tags" do
    before do
      YARD.parse_string <<-'eof'
        # Comments
        # @abstract override me
        # @param [Hash] opts the options
        # @option opts :key ('') hello
        # @option opts :key2 (X) hello
        # @return [String] the result
        # @raise [Exception] Exception class
        # @deprecated for great justice
        # @see A
        # @see http://url.com
        # @see http://url.com Example
        # @author Name
        # @since 1.0
        # @version 1.0
        # @yield a block
        # @yieldparam [String] a a value
        # @yieldreturn [Hash] a hash
        # @example Wash your car
        #   car.wash
        # @example To kill a mockingbird
        #   a = String.new
        #   flip(a.reverse)
        def m(opts = {}) end
      eof
    end

    it "renders text format correctly" do
      text_equals(Registry.at('#m').format(text_options), :tag001)
    end
  end

  describe "param tags on non-methods" do
    it "does not display @param tags on non-method objects" do
      YARD.parse_string <<-'eof'
        # @param [#to_s] name the name
        module Foo; end
      eof

      proc = lambda { Registry.at('Foo').format(html_options) }
      expect(proc).not_to raise_error
    end
  end
end
