RSpec.shared_examples_for 'Msf::DBManager::Import::Libpcap' do
  it { is_expected.to respond_to :import_libpcap }
  it { is_expected.to respond_to :import_libpcap_file }
  it { is_expected.to respond_to :inspect_single_packet }
  it { is_expected.to respond_to :inspect_single_packet_http }
end
