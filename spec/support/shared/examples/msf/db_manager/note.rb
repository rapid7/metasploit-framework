RSpec.shared_examples_for 'Msf::DBManager::Note' do
  it { is_expected.to respond_to :each_note }
  it { is_expected.to respond_to :find_or_create_note }
  it { is_expected.to respond_to :notes }
  it { is_expected.to respond_to :report_note }
end