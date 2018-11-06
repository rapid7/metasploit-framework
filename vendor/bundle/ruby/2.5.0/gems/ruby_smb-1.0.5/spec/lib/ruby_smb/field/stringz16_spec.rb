require 'spec_helper'

RSpec.describe RubySMB::Field::Stringz16 do
  subject(:stringz16) { described_class.new }

  it 'starts as an empty string' do
    expect(stringz16).to eq ''
  end

  context 'with a value already set' do
    let(:abcd) { described_class.new('ABCD') }

    it 'should be UTF-16le' do
      expect(abcd).to eq 'ABCD'.encode('utf-16le')
    end

    it 'should include the NULL terminator on binary output' do
      expect(abcd.to_binary_s).to eq "A\x00B\x00C\x00D\x00\x00\x00"
    end
  end

  context 'with a null terminator in the middle' do
    let(:null_terminator) { described_class.new("ABCD\x00EFG") }

    it 'drops everything after the null terminator' do
      expect(null_terminator).to eq 'ABCD'.encode('utf-16le')
    end
  end

  context 'when reading data in' do
    it 'stops at the first double null byte' do
      io = StringIO.new("A\x00B\x00C\x00D\x00\x00\x00E\x00F\x00")
      stringz16.read(io)
      expect(stringz16.to_binary_s).to eq "A\x00B\x00C\x00D\x00\x00\x00"
    end

    it 'handles a zero length string' do
      io = StringIO.new("\x00\x00A\x00")
      stringz16.read(io)
      expect(stringz16).to eq ''
    end

    it 'fails if no null terminator is found' do
      io = StringIO.new("A\x00B\x00C\x00D\x00")
      expect { stringz16.read(io) }.to raise_error(EOFError)
    end
  end
end
