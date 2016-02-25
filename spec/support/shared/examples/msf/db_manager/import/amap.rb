RSpec.shared_examples_for 'Msf::DBManager::Import::Amap' do
  it { is_expected.to respond_to :import_amap_log }
  it { is_expected.to respond_to :import_amap_log_file }
  it { is_expected.to respond_to :import_amap_mlog }
end
