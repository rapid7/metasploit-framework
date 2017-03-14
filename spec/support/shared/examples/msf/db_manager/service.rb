RSpec.shared_examples_for 'Msf::DBManager::Service' do
  it { is_expected.to respond_to :del_service }
  it { is_expected.to respond_to :each_service }
  it { is_expected.to respond_to :find_or_create_service }
  it { is_expected.to respond_to :get_service }
  it { is_expected.to respond_to :report_service }
  it { is_expected.to respond_to :services }
end