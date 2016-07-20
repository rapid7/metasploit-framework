RSpec.shared_examples_for 'Msf::DBManager::Connection' do
  it { is_expected.to respond_to :active }
  it { is_expected.to respond_to :after_establish_connection }
  it { is_expected.to respond_to :connect }
  it { is_expected.to respond_to :connection_established? }
  it { is_expected.to respond_to :create_db }
  it { is_expected.to respond_to :disconnect }
  it { is_expected.to respond_to :usable }
  it { is_expected.to respond_to :usable= }
end