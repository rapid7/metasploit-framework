require 'spec_helper'

RSpec.describe Msf::Payload::Python do
  describe '#create_exec_stub' do
    let(:python_code) { 'print("hello world");' }

    it 'does not include double quotes' do
      # some usages of this method make this assumption and breaking it would create problems
      expect(described_class.create_exec_stub(python_code)).to_not include('"')
    end

    it 'does not include spaces' do
      expect(described_class.create_exec_stub(python_code)).to_not include(' ')
    end

    it 'does not include semicolons' do
      # this makes sure that the result is a single expression, not a series of statements
      expect(described_class.create_exec_stub(python_code)).to_not include(';')
    end
  end
end
