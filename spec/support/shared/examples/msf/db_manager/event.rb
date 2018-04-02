RSpec.shared_examples_for 'Msf::DBManager::Event' do

  if ENV['REMOTE_DB']
    before {skip("Awaiting proper port")}
  end

  it { is_expected.to respond_to :events }
  it { is_expected.to respond_to :report_event }
end