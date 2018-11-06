require 'spec_helper'

describe Net::NTLM::String do

  it_behaves_like 'a field', 'Foo', false

  let(:active) {
    Net::NTLM::String.new({
        :value  => 'Test',
        :active => true,
        :size   => 4
    })
  }

  let(:inactive) {
    Net::NTLM::String.new({
        :value  => 'Test',
        :active => false,
        :size   => 4
    })
  }

  context '#serialize' do
    it 'should return the value when active' do
      expect(active.serialize).to eq('Test')
    end

    it 'should return an empty string when inactive' do
      expect(inactive.serialize).to eq('')
    end

    it 'should coerce non-string values into strings' do
      active.value = 15
      expect(active.serialize).to eq('15')
    end

    it 'should return empty string on a nil' do
      active.value = nil
      expect(active.serialize).to eq('')
    end
  end

  context '#value=' do
    it 'should set active to false if it empty' do
      active.value = ''
      expect(active.active).to eq(false)
    end

    it 'should adjust the size based on the value set' do
      expect(active.size).to eq(4)
      active.value = 'Foobar'
      expect(active.size).to eq(6)
    end
  end

  context '#parse' do
    it 'should read in a string of the proper size' do
      expect(active.parse('tseT')).to eq(4)
      expect(active.value).to eq('tseT')
    end

    it 'should not read in a string that is too small' do
      expect(active.parse('B')).to eq(0)
      expect(active.value).to eq('Test')
    end

    it 'should be able to read from an offset and only for the given size' do
      expect(active.parse('FooBarBaz',3)).to eq(4)
      expect(active.value).to eq('BarB')
    end
  end
end
