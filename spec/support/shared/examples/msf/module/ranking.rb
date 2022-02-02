RSpec.shared_examples_for 'Msf::Module::Ranking' do
  it { is_expected.to respond_to :rank }
  it { is_expected.to respond_to :rank_to_h }
  it { is_expected.to respond_to :rank_to_s }

  context 'class' do
    subject {
      described_class
    }

    it { is_expected.to respond_to :rank }
    it { is_expected.to respond_to :rank_to_h }
    it { is_expected.to respond_to :rank_to_s }
  end
end