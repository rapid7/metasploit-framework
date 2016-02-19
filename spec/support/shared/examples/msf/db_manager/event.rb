RSpec.shared_examples_for 'Msf::DBManager::Event' do
  it { is_expected.to respond_to :events }
  it { is_expected.to respond_to :report_event }
end