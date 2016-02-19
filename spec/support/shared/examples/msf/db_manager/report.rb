RSpec.shared_examples_for 'Msf::DBManager::Report' do
  it { is_expected.to respond_to :find_or_create_report }
  it { is_expected.to respond_to :report_artifact }
  it { is_expected.to respond_to :report_report }
  it { is_expected.to respond_to :reports }
end