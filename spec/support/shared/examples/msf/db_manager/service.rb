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

    context 'without a task' do
      it 'creates a service' do
        service = subject.report_service(
          host: '192.0.2.1',
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
        expect(service.host.address.to_s).to eq '192.0.2.1'
        expect(service.host.workspace).to eq workspace
        expect(service.task_services).to be_empty
        expect(task.task_services).to be_empty
      end
    end

    context 'with a task and calling multiple times' do
      it 'creates a service' do
        service = 3.times.map do |count|
          subject.report_service(
            host: '192.0.2.1',
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
        expect(service.host.address.to_s).to eq '192.0.2.1'
        expect(service.host.workspace).to eq workspace
        expect(service.task_services.length).to eq 1
        expect(task.task_services.length).to eq 1
      end
    end
  end
end
