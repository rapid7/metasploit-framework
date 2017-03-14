RSpec.shared_examples_for 'Msf::Module::FullName' do
  it { is_expected.to respond_to :fullname }
  it { is_expected.to respond_to :refname }
  it { is_expected.to respond_to :shortname }

  context 'class' do
    subject {
      described_class
    }

    it { is_expected.to respond_to :fullname }
    it { is_expected.to respond_to :refname }
    it { is_expected.to respond_to :refname= }
    it { is_expected.to respond_to :shortname }
  end
end