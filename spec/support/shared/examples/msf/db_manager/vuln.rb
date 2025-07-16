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


  describe '#find_vuln_by_refs', if: !ENV['REMOTE_DB'] do
    let(:workspace) { subject.default_workspace }
    let(:host_addr) { '192.0.2.1' }
    let(:host)      { FactoryBot.create(:mdm_host, address: host_addr, workspace: workspace) }
    let(:service1)  { host.services.create!(port: 5432, proto: 'tcp') }
    let(:service2)  { host.services.create!(port: 80, proto: 'tcp') }
    let(:ref_cve1)  { FactoryBot.create(:mdm_ref, name: 'CVE-2023-0001') }
    let(:ref_cve2)  { FactoryBot.create(:mdm_ref, name: 'CVE-2023-0002') }
    let(:ref_ms)    { FactoryBot.create(:mdm_ref, name: 'MS-1234') }
    let!(:vuln1)    { service1.vulns.create!(host: host, name: 'Vuln1', resource: {uri: '/api'}, refs: [ref_cve1, ref_ms]) }
    let!(:vuln2)    { service1.vulns.create!(host: host, name: 'Vuln2', resource: {uri: '/other'}, refs: [ref_cve2]) }
    let!(:vuln3)    { FactoryBot.create(:mdm_vuln, host: host, name: 'Vuln3', refs: [ref_cve1, ref_cve2]) }
    let!(:vuln4)    { service2.vulns.create!(host: host, name: 'Vuln4', resource: {uri: '/api'}, refs: [ref_ms]) }

    context 'when cve_only is true' do
      it 'finds vuln by service and CVE ref' do
        expect(subject.find_vuln_by_refs([ref_cve1, ref_ms], host, service1, true)).to eq(vuln1)
      end

      it 'returns nil if no CVE refs match' do
        expect(subject.find_vuln_by_refs([ref_ms], host, service1, true)).to be_nil
      end

      it 'finds vuln by CVE ref through host when no service is provided' do
        expect(subject.find_vuln_by_refs([ref_cve2], host, nil, true)).to eq(vuln2)
      end
    end

    context 'when cve_only is false' do
      it 'finds vuln by service and any ref' do
        expect(subject.find_vuln_by_refs([ref_ms], host, service2, false)).to eq(vuln4)
      end

      it 'finds vuln by any ref through host when no service is provided' do
        expect(subject.find_vuln_by_refs([ref_ms], host, nil, false)).to eq(vuln1)
      end
    end

    context 'when resource is specified' do
      it 'finds vuln by service, ref, and resource' do
        expect(subject.find_vuln_by_refs([ref_cve1], host, service1, true, {uri: '/api'})).to eq(vuln1)
      end

      it 'returns nil if resource does not match' do
        expect(subject.find_vuln_by_refs([ref_cve1], host, service1, true, {uri: '/other'})).to be_nil
      end
    end

    context 'when no vulns match' do
      it 'returns nil' do
        ref_unknown = Mdm::Ref.new(name: 'CVE-9999-9999')
        expect(subject.find_vuln_by_refs([ref_unknown], host, service1, true)).to be_nil
      end
    end

    context 'when refs is empty' do
      it 'returns nil' do
        expect(subject.find_vuln_by_refs([], host, service1, true)).to be_nil
      end
    end
  end


  describe '#report_vuln' , if: !ENV['REMOTE_DB']do
    let(:workspace) { subject.default_workspace }
    let(:host) { FactoryBot.create(:mdm_host, workspace: workspace) }
    let(:service) { FactoryBot.create(:mdm_service, host: host) }
    let(:ref1) { FactoryBot.create(:mdm_module_ref, name: 'CVE-2023-0001') }
    let(:ref2) { FactoryBot.create(:mdm_module_ref, name: 'MS-1234') }

    context 'when :host is missing' do
      it 'raises error' do
        expect { subject.report_vuln(name: 'foo') }.to raise_error(ArgumentError, /Missing required option :host/)
      end
    end

    context 'when :data is present' do
      it 'raises error' do
        expect { subject.report_vuln(host: host, name: 'foo', data: 'deprecated') }.to raise_error(ArgumentError, /Deprecated data column/)
      end
    end

    context 'when not active' do
      let(:active) { false }

      it 'returns nil' do
        expect(subject.report_vuln(host: double('host'), name: 'foo')).to be_nil
      end
    end

    context 'when no vuln exists' do
      it 'creates a new vuln' do
        result = subject.report_vuln(host: host, name: 'foo', info: 'desc', workspace: workspace)
        expect(result).to be_a(Mdm::Vuln)
        expect(result.name).to eq('foo')
        expect(result.info).to eq('desc')
        expect(host.vulns).to include(result)
      end
    end

    context 'when the vuln already exists' do
      let(:name) { 'existing vuln' }
      let!(:existing_vuln) { FactoryBot.create(:mdm_vuln, host: host, name: name) }

      it 'returns the vuln with the same name' do
        result = subject.report_vuln(host: host, name: name, workspace: workspace)
        expect(result.id).to eq(existing_vuln.id)
        expect(result.name).to eq(existing_vuln.name)
      end
    end

    context 'with refs' do
      it 'adds `Mdm::Module::Ref` refs' do
        result = subject.report_vuln(host: host, name: 'foo', workspace: workspace, refs: [ref1, ref2])
        expect(result.refs.size).to eq(2)
        expect(result.refs.map(&:name)).to include(ref1.name, ref2.name)
      end

      it 'adds `Msf::Module::SiteReference` refs' do
        ref1 = Msf::Module::SiteReference.from_a(['CVE', '1978-1234'])
        ref2 = Msf::Module::SiteReference.from_a(['URL', 'http://example.com'])
        result = subject.report_vuln(host: host, name: 'foo', workspace: workspace, refs: [ref1, ref2])
        expect(result.refs.size).to eq(2)
        expect(result.refs.map(&:name)).to include("#{ref1.ctx_id}-#{ref1.ctx_val}", "#{ref2.ctx_id}-#{ref2.ctx_val}")
      end

      it 'adds refs as Hash' do
        ref1 = {ctx_id: 'CVE', ctx_val: '1978-1234'}
        ref2 = {ctx_id: 'URL', ctx_val: 'http://example.com'}
        result = subject.report_vuln(host: host, name: 'foo', workspace: workspace, refs: [ref1, ref2])
        expect(result.refs.size).to eq(2)
        expect(result.refs.map(&:name)).to include("#{ref1[:ctx_id]}-#{ref1[:ctx_val]}", "#{ref2[:ctx_id]}-#{ref2[:ctx_val]}")
      end

      it 'adds refs as String' do
        ref1 = 'CVE-1978-1234'
        ref2 = 'http://example.com'
        result = subject.report_vuln(host: host, name: 'foo', workspace: workspace, refs: [ref1, ref2])
        expect(result.refs.size).to eq(2)
        expect(result.refs.map(&:name)).to include(ref1, ref2)
      end
    end

    context 'with name and info' do
      it 'sets them and truncates if too long' do
        long_info = 'a' * 70000
        long_name = 'b' * 300
        result = subject.report_vuln(host: host, name: long_name, info: long_info, workspace: workspace)
        expect(result.name.length).to eq(255)
        expect(result.info.length).to eq(65535)
      end
    end

    context 'with exploited_at' do
      it 'sets exploited_at' do
        now = Time.now
        result = subject.report_vuln(host: host, name: 'foo', workspace: workspace, exploited_at: now)
        expect(result.exploited_at).to eq(now)
      end
    end

    context 'with service as Mdm::Service' do
      it 'sets service' do
        result = subject.report_vuln(host: host, name: 'foo', workspace: workspace, service: service)
        expect(result.service).to eq(service)
      end
    end

    context 'with service as Hash' do
      let (:service_hash) { {name: service.name, port: service.port, proto: service.proto} }

      it 'sets service' do
        expect {
          result = subject.report_vuln(host: host, name: 'foo', workspace: workspace, service: service_hash)
          expect(result.service).to eq(service)
        }.to change(Mdm::Service, :count).by(1)
      end

      context 'with parent services' do
        let(:service2) do
          {name: 'service2', port: 8080, proto: 'tcp'}
        end
        let(:service1) do
          {name: 'service1', port: 8080, proto: 'tcp'}
        end

        context 'with an existing service' do
          it 'creates parent services and add them to the existing service' do
            # Force service creation
            service

            expect {
              service1[:parents] = service2
              service_hash[:parents] = service1
              result = subject.report_vuln(host: host, name: 'foo', workspace: workspace, service: service_hash)

              expect(result.service).to eq(service)

              expect(service.parents.size).to eq(1)
              expect(service.parents.first.name).to eq(service1[:name])
              expect(service.parents.first.port).to eq(service1[:port])
              expect(service.parents.first.proto).to eq(service1[:proto])

              expect(service.parents.first.parents.size).to eq(1)
              expect(service.parents.first.parents.first.name).to eq(service2[:name])
            }.to change(Mdm::Service, :count).by(2)
          end
        end

        context 'with a non-existing service' do
          it 'creates the service and its parent services' do
            expect {
              service1[:parents] = service2
              service_hash = {
                name: 'other service',
                port: 8080,
                proto: 'tcp',
                parents: service1
              }
              result = subject.report_vuln(host: host, name: 'foo', workspace: workspace, service: service_hash)

              expect(result.service).to be_a(Mdm::Service)
              expect(result.service.name).to eq(service_hash[:name])
              expect(result.service.port).to eq(service_hash[:port])
              expect(result.service.proto).to eq(service_hash[:proto])

              expect(result.service.parents.size).to eq(1)
              expect(result.service.parents.first.name).to eq(service1[:name])

              expect(result.service.parents.first.parents.size).to eq(1)
              expect(result.service.parents.first.parents.first.name).to eq(service2[:name])
            }.to change(Mdm::Service, :count).by(3)
          end
        end
      end
    end

    context 'with service and refs' do
      let!(:vuln) do
        ref = FactoryBot.create(:mdm_ref, name: ref1.name)
        service.vulns.create!(host: host, name: 'foo', refs: [ref])
      end

      it 'returns an existing vuln if service and refs match' do
        result = subject.report_vuln(host: host, name: 'foo', workspace: workspace, service: service, refs: [ref1])
        expect(result).to eq(vuln)
      end

      context 'with resource' do
        let(:resource) { {uri: '/api'} }

        it 'returns an existing vuln with the same service, refs and resource' do
          vuln.update!(resource: resource)
          result = subject.report_vuln(host: host, name: 'foo', workspace: workspace, service: service, refs: [ref1], resource: resource)
          expect(result).to eq(vuln)
        end

        it 'creates a new vuln if resource does not match' do
          new_resource = {uri: '/other'}
          result = subject.report_vuln(host: host, name: 'foo', workspace: workspace, service: service, refs: [ref1], resource: new_resource)
          expect(result).not_to eq(vuln)
          expect(result.resource).to eq(new_resource.transform_keys(&:to_s))
        end
      end
    end

    context 'with service and resource' do
      let(:resource) { {uri: '/api'} }
      let!(:vuln) { service.vulns.create!(host: host, name: 'foo', resource: resource) }

      it 'returns an existing vuln if service, name and resource match' do
        result = subject.report_vuln(host: host, name: 'foo', workspace: workspace, service: service, resource: resource)
        expect(result).to eq(vuln)
      end
    end

    context 'without service' do
      it 'does not set any service' do
        result = subject.report_vuln(host: host, name: 'foo', workspace: workspace)
        expect(result.service).to be_nil
      end

      context 'with port' do
        let(:port) { 8080 }

        it 'creates a service with the given port' do
          result = subject.report_vuln(host: host, name: 'foo', workspace: workspace, port: port)
          expect(result.service).not_to be_nil
          expect(result.service.port).to eq(port)
          expect(result.service.proto).to eq('tcp') # default proto
        end

        context 'with proto' do
          let(:proto) { 'udp' }

          it 'creates a service with the given port and proto' do
            result = subject.report_vuln(host: host, name: 'foo', workspace: workspace, port: port, proto: proto)
            expect(result.service).not_to be_nil
            expect(result.service.port).to eq(port)
            expect(result.service.proto).to eq(proto)
          end

          context 'with sname' do
            let(:sname) { 'myservice' }

            it 'creates a service with the given port, proto and sname' do
              result = subject.report_vuln(host: host, name: 'foo', workspace: workspace, port: port, proto: proto, sname: sname)
              expect(result.service).not_to be_nil
              expect(result.service.port).to eq(port)
              expect(result.service.proto).to eq(proto)
              expect(result.service.name).to eq(sname)
            end

            it 'returns the service if it already exists' do
              existing_service = FactoryBot.create(:mdm_service, host: host, port: port, proto: proto, name: sname)
              result = subject.report_vuln(host: host, name: 'foo', workspace: workspace, port: port, proto: proto, sname: sname)
              expect(result.service).to eq(existing_service)
            end
          end
        end
      end

      context 'with resource' do
        let(:resource) { {uri: '/api'} }

        it 'creates a vuln with the resource' do
          result = subject.report_vuln(host: host, name: 'foo', workspace: workspace, resource: resource)
          expect(result.resource).to eq(resource.transform_keys(&:to_s))
        end

        it 'returns an existing vuln if resource matches' do
          existing_vuln = host.vulns.create!(name: 'foo', resource: resource)
          result = subject.report_vuln(host: host, name: 'foo', workspace: workspace, resource: resource)
          expect(result).to eq(existing_vuln)
        end
      end
    end

    context 'with vuln details' do
      let(:vuln_details) { { description: 'desc', proof: 'proof'} }

      it 'sets vuln details' do
        result = subject.report_vuln(host: host, name: 'foo', workspace: workspace, details: vuln_details)
        expect(result.vuln_details.size).to eq(1)
        expect(result.vuln_details.first).to be_a(Mdm::VulnDetail)
        expect(result.vuln_details.first.description).to eq(vuln_details[:description])
        expect(result.vuln_details.first.proof).to eq(vuln_details[:proof])
      end
    end

    context 'with framework events' do
      before :example do
        allow(subject.framework).to receive(:events).and_return(
          double('events', on_db_vuln:nil)
        )
      end

      context 'when a new vuln is created' do
        it 'triggers framework events' do
          vuln = subject.report_vuln(host: host, name: 'foo', workspace: workspace)
          expect(subject.framework.events).to have_received(:on_db_vuln).with(vuln)
        end
      end
    end

  end

end
