RSpec.shared_examples_for 'Msf::DBManager::Vuln' do

  unless ENV['REMOTE_DB']
    it { is_expected.to respond_to :each_vuln }
    it { is_expected.to respond_to :find_vuln_by_refs }
    it { is_expected.to respond_to :find_or_create_vuln }
    it { is_expected.to respond_to :has_vuln? }
    it { is_expected.to respond_to :get_vuln }
    it { is_expected.to respond_to :find_vuln_by_details }
  end

  describe '#report_vuln', if: !ENV['REMOTE_DB'] do
    let(:workspace) do
      subject.default_workspace
    end

    let(:service) do
      subject.report_service(
        host: '192.0.2.1',
        port: '5000',
        name: 'test_service',
        proto: 'tcp',
        info: 'banner',
        workspace: workspace
      )
    end

    context 'without an origin' do
      it 'creates a vuln' do
        vuln = subject.report_vuln(
          host: '192.0.2.1',
          sname: 'AD CS',
          name: "vuln name",
          info: 'vuln info',
          refs: ['https://example.com'],
          workspace: workspace,
          service: service,
        )
        expect(subject.vulns({ workspace: workspace }).count).to eq 1
        expect(vuln.name).to eq 'vuln name'
        expect(vuln.service.name).to eq 'test_service'
        expect(vuln.service.port).to eq 5000
        expect(vuln.info).to eq 'vuln info'
        expect(vuln.host.address.to_s).to eq '192.0.2.1'
        expect(vuln.host.workspace).to eq workspace
        expect(service.task_services).to be_empty
      end
    end
  end

  it { is_expected.to respond_to :vulns }
end
