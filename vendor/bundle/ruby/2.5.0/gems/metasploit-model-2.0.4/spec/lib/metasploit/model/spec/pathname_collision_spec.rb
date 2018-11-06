RSpec.describe Metasploit::Model::Spec::PathnameCollision do
  let(:pathname) do
    Metasploit::Model::Spec.temporary_pathname.join('pathname')
  end

  subject(:pathname_collision) do
    described_class.new(pathname)
  end

  it { is_expected.to be_a Metasploit::Model::Spec::Error }

  context 'check!' do
    subject(:check!) do
      described_class.check!(pathname)
    end

    context 'with existing Pathname' do
      before(:example) do
        pathname.mkpath
      end

      it 'should raise Metasploit::Model::Spec::PathnameCollision' do
        expect {
          check!
        }.to raise_error(described_class)
      end
    end

    context 'without existing Pathname' do
      it 'should not raise error' do
        expect {
          check!
        }.to_not raise_error
      end
    end
  end

  context '#initialize' do
    context '#message' do
      subject(:message) do
        pathname_collision.message
      end

      it 'should include pathname' do
        expect(message).to include("#{pathname} already exists.")
      end

      it 'should include potential cause' do
        expect(message).to include('Metasploit::Model::Spec.remove_temporary_pathname was not called after the previous spec.')
      end
    end
  end
end