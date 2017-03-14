RSpec.shared_examples_for 'Msf::DBManager::Ref' do
  it { is_expected.to respond_to :find_or_create_ref }
  it { is_expected.to respond_to :get_ref }
  it { is_expected.to respond_to :has_ref? }
end