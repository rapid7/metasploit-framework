RSpec.describe Metasploit::Model::Visitation::Visitor, type: :model do
  context 'validations' do
    it { is_expected.to validate_presence_of :block }
    it { is_expected.to validate_presence_of :module_name }
    it { is_expected.to validate_presence_of :parent }
  end

  context '#initialize' do
    subject(:instance) do
      described_class.new(
          :module_name => module_name,
          :parent => parent,
          &block
      )
    end

    let(:block) do
      lambda { |node|
        node
      }
    end

    let(:module_name) do
      'Visited::Node'
    end

    let(:parent) do
      Class.new
    end

    it 'should set #block from &block' do
      expect(instance.block).to eq(block)
    end

    it 'should set #module_name from :module_name' do
      expect(instance.module_name).to eq(module_name)
    end

    it 'should set #parent from :parent' do
      expect(instance.parent).to eq(parent)
    end
  end
end