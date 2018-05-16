RSpec.shared_examples_for 'Msf::DBManager::Ref' do

  if ENV['REMOTE_DB']
    before {skip("Not supported for remote DB")}
  end

  it { is_expected.to respond_to :find_or_create_ref }
  it { is_expected.to respond_to :get_ref }
  it { is_expected.to respond_to :has_ref? }
end