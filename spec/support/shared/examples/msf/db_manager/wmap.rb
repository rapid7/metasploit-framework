RSpec.shared_examples_for 'Msf::DBManager::WMAP' do

  if ENV['REMOTE_DB']
    before {skip("Awaiting wmap port")}
  end

  it { is_expected.to respond_to :create_request }
  it { is_expected.to respond_to :create_target }
  it { is_expected.to respond_to :delete_all_targets }
  it { is_expected.to respond_to :each_distinct_target }
  it { is_expected.to respond_to :each_request }
  it { is_expected.to respond_to :each_request_target }
  it { is_expected.to respond_to :each_request_target_with_body }
  it { is_expected.to respond_to :each_request_target_with_headers }
  it { is_expected.to respond_to :each_request_target_with_path }
  it { is_expected.to respond_to :each_request_target_with_query }
  it { is_expected.to respond_to :each_target }
  it { is_expected.to respond_to :get_target }
  it { is_expected.to respond_to :request_distinct_targets }
  it { is_expected.to respond_to :request_sql }
  it { is_expected.to respond_to :requests }
  it { is_expected.to respond_to :selected_host }
  it { is_expected.to respond_to :selected_id }
  it { is_expected.to respond_to :selected_port }
  it { is_expected.to respond_to :selected_ssl }
  it { is_expected.to respond_to :selected_wmap_target }
  it { is_expected.to respond_to :sql_query }
  it { is_expected.to respond_to :target_requests }
  it { is_expected.to respond_to :targets }
end