# frozen_string_literal: true
require File.dirname(__FILE__) + "/shared_signature_examples"

RSpec.describe YARD::Templates::Helpers::TextHelper do
  include YARD::Templates::Helpers::BaseHelper
  include YARD::Templates::Helpers::TextHelper
  include YARD::Templates::Helpers::MethodHelper

  describe "#signature" do
    before do
      @results = {
        :regular => "root.foo -> Object",
        :default_return => "root.foo -> Hello",
        :no_default_return => "root.foo",
        :private_class => "A.foo -> Object (private)",
        :single => "root.foo -> String",
        :two_types => "root.foo -> (String, Symbol)",
        :two_types_multitag => "root.foo -> (String, Symbol)",
        :type_nil => "root.foo -> Type?",
        :type_array => "root.foo -> Type+",
        :multitype => "root.foo -> (Type, ...)",
        :void => "root.foo -> void",
        :hide_void => "root.foo",
        :block => "root.foo {|a, b, c| ... } -> Object",
        :empty_overload => 'root.foobar -> String'
      }
    end

    def signature(obj) super(obj).strip end

    it_should_behave_like "signature"
  end

  describe "#align_right" do
    it "aligns text right" do
      text = "Method: #some_method (SomeClass)"
      expect(align_right(text)).to eq ' ' * 40 + text
    end

    it "truncates text that is longer than allowed width" do
      text = "(Defined in: /home/user/.rip/.packages/some_gem-2460672e333ac07b9190ade88ec9a91c/long/path.rb)"
      expect(align_right(text)).to eq ' ' + text[0, 68] + '...'
    end
  end

  describe "#h" do
    let(:object) do
      YARD::CodeObjects::MethodObject.new(:root, :foo, :instance).tap do |o|
        o.docstring = "test"
      end
    end

    it "resolves links" do
      expect(h("{include:#foo} 1 2 3").strip).to eq "test 1 2 3"
    end

    it "uses title when present" do
      expect(h("{A b}").strip).to eq "b"
    end

    it "uses object name when no title is present" do
      expect(h("{A}").strip).to eq "A"
    end
  end
end
