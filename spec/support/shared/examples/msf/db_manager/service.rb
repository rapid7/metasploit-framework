RSpec.shared_examples_for 'Msf::DBManager::Service' do

  unless ENV['REMOTE_DB']
    it { is_expected.to respond_to :delete_service }
    it { is_expected.to respond_to :each_service }
  end

  it { is_expected.to respond_to :find_or_create_service }
  it { is_expected.to respond_to :services }
  it { is_expected.to respond_to :report_service }

  describe '#report_service', if: !ENV['REMOTE_DB'] do
    let(:workspace) do
      subject.default_workspace
    end

    let(:task) do
      subject.report_task(workspace: workspace, user: 'test_user', info: 'info', path: 'mock/path')
    end

    let(:host_addr) { '192.0.2.1' }

    context 'without a task' do
      it 'creates a service' do
        service = subject.report_service(
          host: host_addr,
          port: '5000',
          name: 'test_service',
          proto: 'tcp',
          info: 'banner',
          workspace: workspace
        )
        expect(subject.services({ workspace: workspace }).count).to eq 1
        expect(service.name).to eq 'test_service'
        expect(service.port).to eq 5000
        expect(service.proto).to eq 'tcp'
        expect(service.info).to eq 'banner'
        expect(service.host.address.to_s).to eq host_addr
        expect(service.host.workspace).to eq workspace
        expect(service.task_services).to be_empty
        expect(task.task_services).to be_empty
      end
    end

    context 'with a task and calling multiple times' do
      it 'creates a service' do
        service = 3.times.map do |count|
          subject.report_service(
            host: host_addr,
            port: '5000',
            name: 'test_service',
            proto: 'tcp',
            info: "banner #{count}",
            workspace: workspace,
            task: task
          )
        end.last
        expect(subject.services({ workspace: workspace }).count).to eq 1
        expect(service.name).to eq 'test_service'
        expect(service.port).to eq 5000
        expect(service.proto).to eq 'tcp'
        expect(service.info).to eq 'banner 2'
        expect(service.host.address.to_s).to eq host_addr
        expect(service.host.workspace).to eq workspace
        expect(service.task_services.length).to eq 1
        expect(task.task_services.length).to eq 1
      end
    end

    context 'when not active' do
      let(:active) { false }

      it 'returns nil' do
        expect(subject.report_service(host: host_addr, port: 80, proto: 'tcp', workspace: workspace)).to be_nil
      end
    end

    context 'when port is zero' do
      it 'returns nil and logs skipping' do
        expect(subject).to receive(:dlog).with(/Skipping port zero for service '.*' on host '#{host_addr}'/)
        result = subject.report_service(host: host_addr, port: 0, proto: 'tcp', workspace: workspace)
        expect(result).to be_nil
      end
    end

    context 'when creating a new service with required fields' do
      let(:opts) do
        {
          workspace: workspace,
          host: host_addr,
          port: 8080,
          proto: 'tcp'
        }
      end

      it 'creates and returns the service' do
        service = subject.report_service(opts)
        expect(service).to be_persisted
        expect(service.port).to eq(opts[:port])
        expect(service.proto).to eq(opts[:proto])
        expect(service.host.address).to eq(host_addr)
        expect(service.state).to eq(Msf::ServiceState::Open)
        expect(service.info).to be_empty
      end

      context 'with parent services' do
        let(:service2) do
          {name: 'service2', port: 8080, proto: 'tcp'}
        end
        let(:service1) do
          {name: 'service1', port: 8080, proto: 'tcp'}
        end

        it 'creates the service and its parent services' do
          expect {
            service1[:parents] = service2
            opts[:parents] = service1
            result = subject.report_service(opts)

            expect(result.parents.size).to eq(1)
            expect(result.parents.first.name).to eq(service1[:name])
            expect(result.parents.first.port).to eq(service1[:port])
            expect(result.parents.first.proto).to eq(service1[:proto])

            expect(result.parents.first.parents.size).to eq(1)
            expect(result.parents.first.parents.first.name).to eq(service2[:name])
          }.to change(Mdm::Service, :count).by(3)
        end
      end
    end

    context 'when :sname is present' do
      it 'uses :sname as :name and downcases it' do
        opts = { host: host_addr, port: 22, proto: 'tcp', workspace: workspace, sname: 'SSH' }
        service = subject.report_service(opts)
        expect(service.name).to eq('ssh')
      end
    end

    context 'when additional attributes are present' do
      it 'sets them on the service' do
        opts = {
          host: host_addr,
          port: 443,
          proto: 'tcp',
          workspace: workspace,
          name: 'https',
          info: 'nginx 1.18',
          state: 'open',
          resource: {uri: '/api'}
        }
        service = subject.report_service(opts)
        expect(service.name).to eq('https')
        expect(service.info).to eq('nginx 1.18')
        expect(service.state).to eq('open')
        expect(service.resource).to eq({'uri' => '/api'})
      end
    end

    context 'when host is not an Mdm::Host' do
      it 'calls #report_host and uses its result' do
        opts = { host: host_addr, port: 21, proto: 'tcp', workspace: workspace }
        expect(subject).to receive(:report_host).with({workspace: workspace, host: host_addr}).and_call_original
        service = subject.report_service(opts)
        expect(service.host.address).to eq(host_addr)
        expect(service.host.workspace).to eq(workspace)
      end
    end

    context 'with framework events' do
      before :example do
        allow(subject.framework).to receive(:events).and_return(
          double('events', on_db_host:nil, on_db_service: nil, on_db_service_state: nil)
        )
      end

      context 'when a new service is created' do
        it 'triggers framework events' do
          opts = { host: host_addr, port: 3306, proto: 'tcp', workspace: workspace }
          service = subject.report_service(opts)
          expect(subject.framework.events).to have_received(:on_db_service).with(service)
          expect(subject.framework.events).to have_received(:on_db_service_state).with(service, 3306, nil)
        end
      end

      context 'when service state changes' do
        it 'triggers framework state change event' do
          host = FactoryBot.create(:mdm_host, address: host_addr, workspace: workspace)
          service = host.services.create!(port: 5432, proto: 'tcp', state: Msf::ServiceState::Closed)
          opts = { host: host_addr, port: 5432, proto: 'tcp', workspace: workspace, state: Msf::ServiceState::Open }
          subject.report_service(opts)
          expect(subject.framework.events).to have_received(:on_db_service_state).with(service, 5432, Msf::ServiceState::Closed)
        end
      end
    end

    context 'when service already exists' do
      let(:host) { FactoryBot.create(:mdm_host, address: host_addr, workspace: workspace) }
      let(:existing_service) do
        host.services.create!(port: 80, proto: 'tcp', name: 'http', resource: {uri: '/api'})
      end
      let(:opts) do
        {
          workspace: workspace,
          host: host_addr,
          port: existing_service.port,
          proto: existing_service.proto,
          name: existing_service.name
        }
      end

      context 'without resource' do
        it 'returns the existing service' do
          service = subject.report_service(opts)
          expect(service).to eq(existing_service)
        end
      end
      context 'with the same resource' do
        it 'returns the existing service' do
          opts[:resource] = existing_service.resource
          service = subject.report_service(opts)
          expect(service).to eq(existing_service)
        end
      end
      context 'with a different resource' do
        it 'creates a new service' do
          opts[:resource] = {uri: '/new'}
          service = subject.report_service(opts)
          expect(service).not_to eq(existing_service)
          expect(host.services.count).to eq 2
        end
      end

      context 'with parent services' do
        let(:service2) do
          {name: 'service2', port: 8080, proto: 'tcp'}
        end
        let(:service1) do
          {name: 'service1', port: 8080, proto: 'tcp'}
        end

        it 'creates parent services and add them to the existing service' do
          # Force existing service creation
          existing_service

          expect {
            service1[:parents] = service2
            opts[:parents] = service1
            result = subject.report_service(opts)

            expect(result).to eq(existing_service)

            expect(existing_service.parents.size).to eq(1)
            expect(existing_service.parents.first.name).to eq(service1[:name])
            expect(existing_service.parents.first.port).to eq(service1[:port])
            expect(existing_service.parents.first.proto).to eq(service1[:proto])

            expect(existing_service.parents.first.parents.size).to eq(1)
            expect(existing_service.parents.first.parents.first.name).to eq(service2[:name])
          }.to change(Mdm::Service, :count).by(2)
        end
      end

    end

  end


  describe '#process_service_chain', if: !ENV['REMOTE_DB'] do
    let(:workspace) { subject.default_workspace }
    let(:host) { FactoryBot.create(:mdm_host, workspace: workspace) }

    context 'when given valid service parameters' do
      let(:service_hash) do
        {
          name: 'http',
          port: 80,
          proto: 'tcp'
        }
      end

      it 'creates a new service if none exists' do
        expect {
          service = subject.process_service_chain(host, service_hash)
          expect(service).to be_a(Array)
          expect(service.size).to eq(1)
          expect(service.first).to be_a(Mdm::Service)
          expect(service.first.name).to eq('http')
          expect(service.first.port).to eq(80)
          expect(service.first.proto).to eq('tcp')
          expect(service.first.state).to eq(Msf::ServiceState::Open)
        }.to change(Mdm::Service, :count).by(1)
      end

      it 'returns existing service if it already exists' do
        existing_service = FactoryBot.create(
          :mdm_service,
          host: host,
          name: service_hash[:name],
          port: service_hash[:port],
          proto: service_hash[:proto]
        )

        expect {
          service = subject.process_service_chain(host, service_hash).first
          expect(service.id).to eq(existing_service.id)
        }.not_to change(Mdm::Service, :count)
      end

      it 'converts service parameters to expected types' do
        service_hash = {
          name: 'HTTP',  # should be downcased
          port: '80',    # should be converted to integer
          proto: 'TCP'   # should be downcased
        }

        service = subject.process_service_chain(host, service_hash).first
        expect(service.name).to eq('http')
        expect(service.port).to eq(80)
        expect(service.proto).to eq('tcp')
      end

      it 'sets the resource when provided' do
        service_hash[:resource] = 'test_resource'

        service = subject.process_service_chain(host, service_hash).first
        expect(service.resource).to eq('test_resource')
      end
    end

    context 'with parent services' do
      it 'processes a single parent service' do
        parent_hash = {
          name: 'ssl',
          port: 443,
          proto: 'tcp'
        }

        service_hash = {
          name: 'https',
          port: 443,
          proto: 'tcp',
          parents: parent_hash
        }

        expect {
          service = subject.process_service_chain(host, service_hash).first
          expect(service.parents.count).to eq(1)
          expect(service.parents.first.name).to eq('ssl')
          expect(service.parents.first.port).to eq(443)
        }.to change(Mdm::Service, :count).by(2)
      end

      it 'processes multiple parent services' do
        parent_hash1 = {
          name: 'https',
          port: 443,
          proto: 'tcp'
        }

        parent_hash2 = {
          name: 'http',
          port: 80,
          proto: 'tcp'
        }

        service_hash = {
          name: 'webapp',
          port: 80,
          proto: 'tcp',
          parents: [parent_hash1, parent_hash2]
        }

        expect {
          service = subject.process_service_chain(host, service_hash).first
          expect(service.parents.count).to eq(2)
          expect(service.parents.map(&:name)).to include('https', 'http')
        }.to change(Mdm::Service, :count).by(3)
      end

      it 'handles nested parent services' do
        grandparent_hash = {
          name: 'tcp',
          port: 443,
          proto: 'tcp'
        }

        parent_hash = {
          name: 'ssl',
          port: 443,
          proto: 'tcp',
          parents: grandparent_hash
        }

        service_hash = {
          name: 'https',
          port: 443,
          proto: 'tcp',
          parents: parent_hash
        }

        expect {
          service = subject.process_service_chain(host, service_hash).first
          parent = service.parents.first
          expect(parent.name).to eq('ssl')
          expect(parent.parents.first.name).to eq('tcp')
        }.to change(Mdm::Service, :count).by(3)
      end
    end

    context 'with invalid parameters' do
      it 'returns nil if service hash is nil' do
        expect(subject.process_service_chain(host, nil)).to be_nil
      end

      it 'returns nil if host is nil' do
        service_hash = { name: 'http', port: 80, proto: 'tcp' }
        expect(subject.process_service_chain(nil, service_hash)).to be_nil
      end

      it 'returns nil if required service parameters are missing' do
        # Missing port
        expect(subject.process_service_chain(host, { name: 'http', proto: 'tcp' })).to be_nil

        # Missing proto
        expect(subject.process_service_chain(host, { name: 'http', port: 80 })).to be_nil
      end
    end
  end



end
