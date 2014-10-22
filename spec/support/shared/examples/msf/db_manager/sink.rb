shared_examples_for 'Msf::DBManager::Sink' do
  it { is_expected.to respond_to :initialize_sink }
  it { is_expected.to respond_to :queue }
  it { is_expected.to respond_to :sink }
  it { is_expected.to respond_to :sink= }
  it { is_expected.to respond_to :sync }
end