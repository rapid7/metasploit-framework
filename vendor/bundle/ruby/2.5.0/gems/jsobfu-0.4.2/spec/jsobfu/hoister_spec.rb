require 'spec_helper'

describe JSObfu::Hoister do
  let(:code)        { '' }
  let(:ast)         { RKelly::Parser.new.parse(code) }
  subject(:hoister) { described_class.new }

  describe "#scope" do

    context 'when given Javascript code that declares var i' do
      let(:code) { "var i = 3;" }

      it 'has only the key "i" in its scope' do
        hoister.accept(ast)
        expect(hoister.scope.keys).to eq %w(i)
      end
    end

    context 'when given Javascript code that declares var i, and an anonymous inner function that declares var j' do
      let(:code) { "var i = 3; (function() { var j = 3; return j; })();" }

      it 'has only the key "i" in its scope' do
        hoister.accept(ast)
        expect(hoister.scope.keys).to eq %w(i)
      end
    end

    context 'when given Javascript code that declares var i, and an inner function named j' do
      let(:code) { "var i = 3; function j() { return 0x55; }" }

      it 'has the key "i" and "j" in its scope' do
        hoister.accept(ast)
        expect(hoister.scope.keys).to match_array %w(i j)
      end

      it 'has the key "j" in its #functions' do
        hoister.accept(ast)
        expect(hoister.functions).to match_array %w(j)
      end
    end

    context 'when given Javascript code that refers to i, then later declares var i' do
      let(:code) { "window.x = window.x || i; var i = 10;" }

      it 'has the key "i" in its scope' do
        hoister.accept(ast)
        expect(hoister.scope.keys).to eq %w(i)
      end
    end
  end

  describe "#scope_declaration" do
    context 'when scope has the keys "a", "b", and "c"' do
      before { allow(hoister).to receive(:scope).and_return({a:1,b:2,c:3}) }

      it 'returns the string "var a,b,c"' do
        expect(hoister.scope_declaration(shuffle: false)).to eq "var a,b,c;"
      end
    end

    context 'when the scope is empty' do
      before { allow(hoister).to receive(:scope).and_return({}) }
      it 'returns ""' do
        expect(hoister.scope_declaration(shuffle: false)).to eq ""
      end
    end
  end
end
