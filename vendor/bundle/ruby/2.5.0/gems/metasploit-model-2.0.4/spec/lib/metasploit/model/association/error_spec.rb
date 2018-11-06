RSpec.describe Metasploit::Model::Association::Error do
  context '#initialize' do
    let(:attributes) do
      {
          :model => model,
          :name => :associated_things
      }
    end

    let(:model) do
      Class.new
    end

    context 'without :model' do
      before(:example) do
        attributes.delete(:model)
      end

      it 'should raise KeyError' do
        expect {
          described_class.new(attributes)
        }.to raise_error(KeyError)
      end
    end

    context 'without :name' do
      before(:example) do
        attributes.delete(:name)
      end

      it 'should raise KeyError' do
        expect {
          described_class.new(attributes)
        }.to raise_error(KeyError)
      end
    end

    context 'with :model and :name' do
      it 'should not raise error' do
        expect {
          described_class.new(attributes)
        }.to_not raise_error
      end
    end
  end
end