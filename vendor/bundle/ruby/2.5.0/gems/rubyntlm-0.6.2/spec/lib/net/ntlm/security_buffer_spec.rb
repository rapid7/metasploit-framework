require 'spec_helper'

describe Net::NTLM::SecurityBuffer do

  fields = [
      { :name => :length, :class => Net::NTLM::Int16LE, :value => 0, :active => true },
      { :name => :allocated, :class => Net::NTLM::Int16LE, :value => 0, :active => true },
      { :name => :offset, :class => Net::NTLM::Int32LE, :value => 0, :active => true },
  ]

  it_behaves_like 'a fieldset', fields
  it_behaves_like 'a field', 'WORKSTATION', true


  subject(:domain_security_buffer) do
    Net::NTLM::SecurityBuffer.new({
        :value => 'WORKSTATION',
        :active => true
    })
  end

  context 'when setting the value directly' do
    before(:each) do
      domain_security_buffer.value = 'DOMAIN1'
    end
    it 'should change the value' do
      expect(domain_security_buffer.value).to eq('DOMAIN1')
    end

    it 'should adjust the length field to the size of the new value' do
      expect(domain_security_buffer.length).to eq(7)
    end

    it 'should adjust the allocated field to the size of the new value' do
      expect(domain_security_buffer.allocated).to eq(7)
    end
  end

  context '#data_size' do
    it 'should return the size of the value if active' do
      expect(domain_security_buffer.data_size).to eq(11)
    end

    it 'should return 0 if inactive' do
      domain_security_buffer.active = false
      expect(domain_security_buffer.data_size).to eq(0)
    end
  end

  context '#parse' do
    it 'should read in a properly formatted string' do
      # Length of the string is 8
      length = "\x08\x00"
      # Space allocated is 8
      allocated = "\x08\x00"
      # The offset that the actual value begins at is also 8
      offset = "\x08\x00\x00\x00"
      string_to_parse = "#{length}#{allocated}#{offset}FooBarBaz"
      expect(domain_security_buffer.parse(string_to_parse)).to eq(8)
      expect(domain_security_buffer.value).to eq('FooBarBa')
    end

  end
end
