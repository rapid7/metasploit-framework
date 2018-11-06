require 'spec_helper'

describe JSObfu::Disable do

  let(:test_str)  { 'alert("JOE");' }
  let(:signature) { 'JOE' }
  
  context 'before calling JSObfu.disabled = true' do
    it 'obfuscates the string' do
      expect(JSObfu.new(test_str).obfuscate.to_s).not_to include(signature)
    end
  end

  context 'after calling JSObfu.disabled = true' do

    before { JSObfu.disabled = true }
    after { JSObfu.disabled = false }

    it 'does not obfuscate the string' do
      expect(JSObfu.new(test_str).obfuscate.to_s).to include(signature)
    end

    context 'and then calling JSObfu.disabled = false' do
      before { JSObfu.disabled = false }

      it 'obfuscates the string' do
        expect(JSObfu.new(test_str).obfuscate.to_s).not_to include(signature)
      end
    end

  end

end
