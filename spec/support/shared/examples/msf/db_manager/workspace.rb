RSpec.shared_examples_for 'Msf::DBManager::Workspace' do
  it { is_expected.to respond_to :add_workspace }
  it { is_expected.to respond_to :default_workspace }
  it { is_expected.to respond_to :find_workspace }
  it { is_expected.to respond_to :workspace }
  it { is_expected.to respond_to :workspace= }
  it { is_expected.to respond_to :workspaces }
end