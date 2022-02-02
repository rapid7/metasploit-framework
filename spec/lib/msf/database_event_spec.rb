RSpec.describe Msf::DatabaseEvent do
  subject(:base_instance) {
    base_class.new
  }

  let(:base_class) {
    described_class = self.described_class

    Class.new do
      include described_class
    end
  }

  it { is_expected.to respond_to :on_db_client }
  it { is_expected.to respond_to :on_db_host }
  it { is_expected.to respond_to :on_db_host_state }
  it { is_expected.to respond_to :on_db_ref }
  it { is_expected.to respond_to :on_db_service }
  it { is_expected.to respond_to :on_db_service_state }
  it { is_expected.to respond_to :on_db_vuln }

end