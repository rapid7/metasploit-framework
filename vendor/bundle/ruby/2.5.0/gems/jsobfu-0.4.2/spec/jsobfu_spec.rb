require 'spec_helper'
require 'execjs'

describe JSObfu do

  let(:js) { 'var x; function y() {};' }

  subject(:jsobfu) do
    described_class.new(js)
  end

  describe '#sym' do

    let(:iterations) { 1 }

    before do
      jsobfu.obfuscate(iterations: iterations)
    end

    context 'when given the string "x"' do
      it 'returns some string' do
        expect(jsobfu.sym('x')).not_to be_nil
      end
    end

    context 'when given the string "YOLOSWAG"' do
      it 'returns nil' do
        expect(jsobfu.sym('YOLOSWAG')).to be_nil
      end
    end

    context 'when iterations: 2 is passed to obfuscate()' do
      let(:iterations) { 2 }

      context 'when given the string "x"' do
        it 'returns some string' do
          expect(jsobfu.sym('x')).not_to be_nil
        end
      end

      context 'when given the string "YOLOSWAG"' do
        it 'returns nil' do
          expect(jsobfu.sym('YOLOSWAG')).to be_nil
        end
      end
    end
  end

  describe '#obfuscate' do

    describe 'the :iterations option' do

      describe 'when :iterations is 1' do

        let(:js) { 'this.test = function() { return 5; }' }

        it 'evaluates to the same result as when :iterations is 5' do
          obfu1 = described_class.new(js).obfuscate(iterations: 1).to_s
          obfu5 = described_class.new(js).obfuscate(iterations: 5).to_s
          expect(obfu1).to evaluate_to(obfu5)
        end
      end

    end

    describe 'the :memory_sensitive option' do

      let(:match) { "ABCDEFG" }
      let(:js) { "var x = '#{match}'" }

      describe 'when true' do
        10.times do

          it 'does not obfuscate String literals' do
            expect(jsobfu.obfuscate(memory_sensitive: true).to_s).to include(match)
          end

        end
      end

      describe 'when false' do
        10.times do

          it 'obfuscates String literals' do
            expect(jsobfu.obfuscate(memory_sensitive: false).to_s).not_to include(match)
          end

        end
      end

    end

    describe 'preserving the variable map across calls' do

      let(:code1) { 'var Blah = 1;' }
      let(:code2) { 'this.test = function(){ return Blah + 1; };' }

      describe 'when calling obfuscate again after changing the code' do

        it 'preserves the variable map' do
          js = JSObfu.new(code1)
          obf1 = js.obfuscate.to_s
          js.code = code2
          obf2 = js.obfuscate.to_s

          expect(obf1+obf2).to evaluate_to(code1+code2)
        end

      end

      describe 'when calling obfuscate twice after changing the code' do

        let(:code2) { 'var Foo = 2;' }
        let(:code3) { 'this.test = function(){ return Blah + Foo + 1; };' }

        it 'preserves the variable map' do
          js = JSObfu.new

          js.code = code1
          obf1 = js.obfuscate.to_s
          js.code = code2
          obf2 = js.obfuscate.to_s
          js.code = code3
          obf3 = js.obfuscate.to_s

          expect(obf1+obf2+obf3).to evaluate_to(code1+code2+code3)
        end

      end

    end

  end

end
