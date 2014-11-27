require 'spec_helper'
require 'rex/exploitation/jsobfu'

describe Rex::Exploitation::JSObfu do
  TEST_JS = %Q|
    function x() {
      alert('1');
    };

    x();
  |

  subject(:jsobfu) do
    described_class.new(TEST_JS)
  end

  describe '#obfuscate' do
    
    it 'returns a #to_s object' do
      expect(jsobfu.obfuscate.to_s).to be_a(String)
    end

    it 'returns a non-empty String' do
      expect(jsobfu.obfuscate.to_s).not_to be_empty
    end

  end

end
