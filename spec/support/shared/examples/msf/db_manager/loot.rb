RSpec.shared_examples_for 'Msf::DBManager::Loot' do
  it { is_expected.to respond_to :each_loot }
  it { is_expected.to respond_to :find_or_create_loot }
  it { is_expected.to respond_to :loots }
  it { is_expected.to respond_to :report_loot }
end