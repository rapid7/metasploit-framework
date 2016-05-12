RSpec.shared_examples_for 'Msf::Module::Type' do
  it { is_expected.to respond_to :auxiliary? }
  it { is_expected.to respond_to :encoder? }
  it { is_expected.to respond_to :exploit? }
  it { is_expected.to respond_to :nop? }
  it { is_expected.to respond_to :payload? }
  it { is_expected.to respond_to :post? }
  it { is_expected.to respond_to :type }

  context 'class' do
    subject {
      described_class
    }

    it { is_expected.to respond_to :type }
  end
end