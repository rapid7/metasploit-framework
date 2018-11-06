RSpec.describe Metasploit::Model::Association::Reflection, type: :model do
  context 'validations' do
    it { is_expected.to validate_presence_of :model }
    it { is_expected.to validate_presence_of :name }
    it { is_expected.to validate_presence_of :class_name }
  end

  context '#klass' do
    subject(:klass) do
      reflection.klass
    end


    let(:class_name) do
      FactoryGirl.generate :metasploit_model_association_reflection_class_name
    end

    let(:class_name_class) do
      Class.new
    end

    let(:model) do
      Class.new
    end

    let(:name) do
      FactoryGirl.generate :metasploit_model_association_reflection_name
    end

    let(:reflection) do
      described_class.new(
          :model => model,
          :name => name,
          :class_name => class_name
      )
    end

    before(:example) do
      stub_const(class_name, class_name_class)
    end

    it 'should return Class with Class#name #class_name' do
      expect(klass).to eq(class_name_class)
    end
  end
end