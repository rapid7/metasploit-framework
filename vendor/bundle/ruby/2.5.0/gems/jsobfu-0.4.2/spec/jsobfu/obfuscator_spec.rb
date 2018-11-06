require 'spec_helper'
require 'rkelly'

describe JSObfu::Obfuscator do
  let(:opts) { { } }
  subject(:obfuscator) { described_class.new(opts) }

  describe 'the :global option' do
    let(:global_str) { 'BLAHBLAH' }
    let(:opts) { { global: global_str } }
    let(:simple_js) { 'x;' }
    let(:simple_ast) { RKelly::Parser.new.parse(simple_js) }

    it 'rewrites unresolved lookups as property lookups on the specified global object' do
      expect(obfuscator.accept(simple_ast).to_s).to include(global_str)
    end

    context 'when the code contains `this`' do
      let(:simple_js) { 'this;' }
      it 'never rewrites `this`' do
        expect(obfuscator.accept(simple_ast).to_s).not_to include(global_str)
      end
    end

    context 'when the global object is specified' do
      let(:global_str) { 'mywindow2' }
      let(:simple_js) { "mywindow2;" }
      it 'never rewrites itself' do
        expect(obfuscator.accept(simple_ast).to_s).to eq(simple_js)
      end
    end
  end

  describe 'when encountering the void() keyword' do

    let(:opts) { { iterations: 3 } }
    let(:simple_js) { "void(null);" }
    let(:simple_ast) { RKelly::Parser.new.parse(simple_js) }

    it 'does not rewrite the void() call as a global property lookup' do
      expect(obfuscator.accept(simple_ast).to_s).not_to include("window")
    end

    it 'does not obfuscate the keyword void' do
      expect(obfuscator.accept(simple_ast).to_s).to include("void")
    end

  end

end
