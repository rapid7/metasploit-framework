RSpec.describe Mdm::Service, type: :model do
  it_should_behave_like 'Metasploit::Concern.run'

  context 'CONSTANTS' do
    context 'PROTOS' do
      subject(:protos) {
        described_class::PROTOS
      }

      it { is_expected.to include 'tcp' }
      it { is_expected.to include 'udp' }
    end

    context 'STATES' do
      subject(:states) {
        described_class::STATES
      }

      it { is_expected.to include 'closed' }
      it { is_expected.to include 'filtered' }
      it { is_expected.to include 'open' }
      it { is_expected.to include 'unknown' }
    end
  end

  context "Associations" do

    it { is_expected.to have_many(:task_services).class_name('Mdm::TaskService').dependent(:destroy) }
    it { is_expected.to have_many(:tasks).class_name('Mdm::Task').through(:task_services) }
    it { is_expected.to have_many(:creds).class_name('Mdm::Cred').dependent(:destroy) }
    it { is_expected.to have_many(:exploited_hosts).class_name('Mdm::ExploitedHost').dependent(:destroy) }
    it { is_expected.to have_many(:notes).class_name('Mdm::Note').dependent(:destroy) }
    it { is_expected.to have_many(:vulns).class_name('Mdm::Vuln').dependent(:destroy) }
    it { is_expected.to have_many(:web_sites).class_name('Mdm::WebSite').dependent(:destroy) }
    it { is_expected.to have_many(:web_pages).class_name('Mdm::WebPage').through(:web_sites) }
    it { is_expected.to have_many(:web_forms).class_name('Mdm::WebForm').through(:web_sites) }
    it { is_expected.to have_many(:web_vulns).class_name('Mdm::WebVuln').through(:web_sites) }
    it { is_expected.to belong_to(:host).class_name('Mdm::Host') }
  end

  context 'scopes' do
    context "inactive" do
      it "should exclude open services" do
        open_service = FactoryBot.create(:mdm_service, :state => 'open')
        expect(Mdm::Service.inactive).not_to include(open_service)
      end
    end

    context "with_state open" do
      it "should exclude closed services" do
        closed_service = FactoryBot.create(:mdm_service, :state => 'closed')
        expect(Mdm::Service.with_state('open')).not_to include(closed_service)
      end
    end

    context 'search' do
      it 'should find only services that match for \'tcp\'' do
        tcp_service   = FactoryBot.create(:mdm_service, proto: 'tcp')
        udp_service    =  FactoryBot.create(:mdm_service, proto: 'udp')
        search_results = Mdm::Service.search('tcp')
        expect(search_results).to     include(tcp_service)
        expect(search_results).not_to include(udp_service)
      end

      it 'should query host name of services' do
        service = FactoryBot.create(:mdm_service)
        host_name = service.host.name
        expect(Mdm::Service.search(host_name)).to include(service)
      end
    end
  end

  context 'callbacks' do
    context 'after_save' do
      include_context 'Rex::Text'

      it 'should call #normalize_host_os' do
        svc = FactoryBot.create(:mdm_service)
        expect(svc).to receive(:normalize_host_os)
        svc.run_callbacks(:save)
      end

      it 'should include recog data when there is a match' do
        host = FactoryBot.create(:mdm_host)
        FactoryBot.create(
          :mdm_service,
          :host => host,
          :name => 'ftp',
          :info => 'example.com Microsoft FTP Service (Version 3.0).'
        )
        expect(host.name).to eq('example.com')
        expect(host.os_name).to eq('Windows NT')
      end

      it 'should not include recog data when there is not a match' do
        host = FactoryBot.create(:mdm_host)
        FactoryBot.create(
          :mdm_service,
          :host => host,
          :name => 'ftp',
          :info => 'THISSHOULDNEVERMATCH'
        )
        expect(host.os_name).to eq('Unknown')
      end
    end
  end

  context 'factory' do
    it 'should be valid' do
      service = FactoryBot.build(:mdm_service)
      expect(service).to be_valid
    end
  end

  context '#destroy' do
    it 'should successfully destroy the object' do
      service = FactoryBot.create(:mdm_service)
      expect {
        service.destroy
      }.to_not raise_error
      expect {
        service.reload
      }.to raise_error(ActiveRecord::RecordNotFound)
    end
  end

  context 'database' do

    context 'timestamps'do
      it { is_expected.to have_db_column(:created_at).of_type(:datetime) }
      it { is_expected.to have_db_column(:updated_at).of_type(:datetime) }
    end

    context 'columns' do
      it { is_expected.to have_db_column(:host_id).of_type(:integer) }
      it { is_expected.to have_db_column(:port).of_type(:integer).with_options(:null => false) }
      it { is_expected.to have_db_column(:proto).of_type(:string).with_options(:null => false) }
      it { is_expected.to have_db_column(:state).of_type(:string) }
      it { is_expected.to have_db_column(:name).of_type(:string) }
      it { is_expected.to have_db_column(:info).of_type(:text) }
    end

    context 'indices' do
      it { is_expected.to have_db_index(:name) }
      it { is_expected.to have_db_index(:port) }
      it { is_expected.to have_db_index(:proto) }
      it { is_expected.to have_db_index(:state) }
    end
  end

  context 'search' do
    let(:base_class) {
      described_class
    }

    context 'attributes' do
      it_should_behave_like 'search_attribute',
                            :info,
                            type: :string
      it_should_behave_like 'search_attribute',
                            :name,
                            type: :string
      it_should_behave_like 'search_attribute',
                            :proto,
                            type: {
                                set: :string
                            }
      it_should_behave_like 'search_with',
                             MetasploitDataModels::Search::Operator::Port::List,
                             name: :port
    end

    context 'associations' do
      it_should_behave_like 'search_association', :host
    end
  end

  context "validations" do

    context 'port' do
      it 'should require a port' do
        portless_service= FactoryBot.build(:mdm_service, :port => nil)
        expect(portless_service).not_to be_valid
        expect(portless_service.errors[:port]).to include("is not a number")
      end

      it 'should not be valid for out-of-range numbers' do
        out_of_range = FactoryBot.build(:mdm_service, :port => 70000)
        expect(out_of_range).not_to be_valid
        expect(out_of_range.errors[:port]).to include("is not included in the list")
      end

      it 'should not be valid for port 0' do
        out_of_range = FactoryBot.build(:mdm_service, :port => 0)
        expect(out_of_range).not_to be_valid
        expect(out_of_range.errors[:port]).to include("is not included in the list")
      end

      it 'should not be valid for decimal numbers' do
        out_of_range = FactoryBot.build(:mdm_service, :port => 5.67)
        expect(out_of_range).not_to be_valid
        expect(out_of_range.errors[:port]).to include("must be an integer")
      end

      it 'should not be valid for a negative number' do
        out_of_range = FactoryBot.build(:mdm_service, :port => -8)
        expect(out_of_range).not_to be_valid
        expect(out_of_range.errors[:port]).to include("is not included in the list")
      end
    end

    subject(:mdm_service) {
      FactoryBot.build(:mdm_service)
    }

    it 'validate port is only an integer' do
      is_expected.to validate_numericality_of(:port).only_integer
    end

    it { is_expected.to validate_inclusion_of(:proto).in_array(described_class::PROTOS) }

    context 'when a duplicate service already exists' do
      let(:service1) { FactoryBot.create(:mdm_service)}
      let(:service2) { FactoryBot.build(:mdm_service, :host => service1.host, :port => service1.port, :proto => service1.proto )}
      it 'is not valid' do
        expect(service2).to_not be_valid
      end
    end

  end
end
