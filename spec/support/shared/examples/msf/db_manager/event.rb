RSpec.shared_examples_for 'Msf::DBManager::Event' do

  unless ENV['REMOTE_DB']
    it { is_expected.to respond_to :events }
  end

  it { is_expected.to respond_to :report_event }
end