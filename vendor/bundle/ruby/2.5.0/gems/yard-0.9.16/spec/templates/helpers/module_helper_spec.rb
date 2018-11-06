# frozen_string_literal: true

RSpec.describe YARD::Templates::Helpers::ModuleHelper do
  include YARD::Templates::Helpers::BaseHelper
  include YARD::Templates::Helpers::ModuleHelper

  describe "#prune_method_listing" do
    before { YARD::Registry.clear }
    let(:options) { OpenStruct.new }
    let(:object) { YARD::Registry.at("Foo#bar") }
    let(:objects) { [object] }

    it "filters aliases" do
      YARD.parse_string "class Foo; def orig; end; alias bar orig end"
      expect(prune_method_listing(objects)).to eq []
    end

    it "filters attributes" do
      YARD.parse_string "class Foo; attr_accessor :bar end"
      expect(prune_method_listing(objects)).to eq []
    end

    it "ignores methods if namespace object is filtered" do
      YARD.parse_string <<-eof
        # @author test
        class Foo
          def bar; end
        end
      eof

      options.verifier = YARD::Verifier.new('@author.text != "test"')
      expect(prune_method_listing(objects)).to eq []
    end
  end
end
