# -*- coding: binary -*-

require 'spec_helper'

def config_wrapper(config)
  { 'scrape_configs' => config }
end

RSpec.describe Msf::Auxiliary::Prometheus do
  class DummyPrometheusClass
    include Msf::Auxiliary::Prometheus
    def framework
      Msf::Simple::Framework.create(
        'ConfigDirectory' => Rails.root.join('spec', 'dummy', 'framework', 'config').to_s,
        # don't load any module paths so we can just load the module under test and save time
        'DeferModuleLoads' => true
      )
    end

    def active_db?
      true
    end

    def print_good(_str = nil)
      raise StandardError, 'This method needs to be stubbed.'
    end

    def store_cred(_hsh = nil)
      raise StandardError, 'This method needs to be stubbed.'
    end

    def fullname
      'auxiliary/gather/prometheus'
    end

    def myworkspace
      raise StandardError, 'This method needs to be stubbed.'
    end
  end

  subject(:aux_prometheus) { DummyPrometheusClass.new }

  let!(:workspace) { FactoryBot.create(:mdm_workspace) }

  context '#create_credential_and_login' do
    let(:session) { FactoryBot.create(:mdm_session) }
    let(:user) { FactoryBot.create(:mdm_user) }
    subject(:test_object) { DummyPrometheusClass.new }
    let(:workspace) { FactoryBot.create(:mdm_workspace) }
    let(:service) { FactoryBot.create(:mdm_service, host: FactoryBot.create(:mdm_host, workspace: workspace)) }
    let(:task) { FactoryBot.create(:mdm_task, workspace: workspace) }
    let(:login_data) do
      {
        address: service.host.address,
        port: service.port,
        service_name: service.name,
        protocol: service.proto,
        workspace_id: workspace.id,
        origin_type: :service,
        module_fullname: 'auxiliary/scanner/smb/smb_login',
        realm_key: 'Active Directory Domain',
        realm_value: 'contosso',
        username: 'Username',
        private_data: 'password',
        private_type: :password,
        status: Metasploit::Model::Login::Status::UNTRIED
      }
    end

    it 'creates a Metasploit::Credential::Login' do
      expect { test_object.create_credential_and_login(login_data) }.to change { Metasploit::Credential::Login.count }.by(1)
    end
    it 'associates the Metasploit::Credential::Core with a task if passed' do
      login = test_object.create_credential_and_login(login_data.merge(task_id: task.id))
      expect(login.tasks).to include(task)
    end

    describe '#process_node_exporter_data' do
      context 'correctly processes nil' do
        it 'returns a nil' do
          expect(subject.process_results_page(nil)).to eql(nil)
        end
      end

      context 'correctly processes non-data lines' do
        it 'returns an empty hash' do
          expect(subject.process_results_page('# some description')).to eql([])
        end
      end

      context 'correctly processes line with no labels and a double value' do
        it 'returns a hash' do
          expect(subject.process_results_page('go_memstats_alloc_bytes 1.605264e+06')).to eql([{ 'go_memstats_alloc_bytes' => { 'labels' => {}, 'value' => '1.605264e+06' } }])
        end
      end

      context 'correctly processes line with no labels and an integer value' do
        it 'returns a hash' do
          expect(subject.process_results_page('go_memstats_alloc_bytes 1')).to eql([{ 'go_memstats_alloc_bytes' => { 'labels' => {}, 'value' => '1' } }])
        end
      end

      context 'correctly processes line with simple label containing empty value' do
        it 'returns a hash' do
          expect(subject.process_results_page('go_gc_duration_seconds{quantile=""} 2.8197e-05')).to eql([{ 'go_gc_duration_seconds' => { 'value' => '2.8197e-05', 'labels' => { 'quantile' => '' } } }])
        end
      end

      context 'correctly processes line with simple label containing value' do
        it 'returns a hash' do
          expect(subject.process_results_page('go_gc_duration_seconds{quantile="1"} 2.8197e-05')).to eql([{ 'go_gc_duration_seconds' => { 'value' => '2.8197e-05', 'labels' => { 'quantile' => '1' } } }])
        end
      end

      context 'correctly processes line with complex label containing values' do
        it 'returns a hash' do
          expect(subject.process_results_page('node_filesystem_avail_bytes{device="/dev/sda1",fstype="vfat",mountpoint="/boot/efi"} 1.118629888e+09')).to eql([{ 'node_filesystem_avail_bytes' => { 'value' => '1.118629888e+09', 'labels' => { 'device' => '/dev/sda1', 'fstype' => 'vfat', 'mountpoint' => '/boot/efi' } } }])
        end
      end

      context 'correctly processes multiple line with complex label containing values' do
        it 'returns a hash' do
          expect(subject.process_results_page("node_filesystem_avail_bytes{device=\"/dev/sda1\",fstype=\"vfat\",mountpoint=\"/boot/efi\"} 1.118629888e+09\n"\
          'node_filesystem_avail_bytes{device="/dev/sda2",fstype="vfat",mountpoint="/boot/efi2"} 1.118629888e+09')).to eql([
            {
              'node_filesystem_avail_bytes' =>
                         {
                           'labels' =>
                                        { 'device' => '/dev/sda1', 'fstype' => 'vfat', 'mountpoint' => '/boot/efi' },
                           'value' => '1.118629888e+09'
                         }
            },
            {
              'node_filesystem_avail_bytes' =>
                {
                  'labels' =>
                              { 'device' => '/dev/sda2', 'fstype' => 'vfat', 'mountpoint' => '/boot/efi2' },
                  'value' => '1.118629888e+09'
                }
            }
          ])
        end
      end
    end

    # https://raw.githubusercontent.com/prometheus/prometheus/release-2.46/config/testdata/conf.good.yml
    context 'prometheus_config_eater correctly processes static_config targets' do
      before(:example) do
        expect(aux_prometheus).to receive(:myworkspace).at_least(:once).and_return(workspace)
      end

      it 'stores creds and prints a table' do
        expect(aux_prometheus).to receive(:create_credential_and_login).with(
          {
            address: 'localhost',
            module_fullname: 'auxiliary/gather/prometheus',
            origin_type: :service,
            port: 9090,
            private_data: 'password',
            private_type: :password,
            protocol: 'tcp',
            service_name: 'https',
            status: Metasploit::Model::Login::Status::UNTRIED,
            username: 'user',
            workspace_id: workspace.id
          }
        )

        expect(aux_prometheus).to receive(:create_credential_and_login).with(
          {
            address: 'localhost',
            module_fullname: 'auxiliary/gather/prometheus',
            origin_type: :service,
            port: 80,
            private_data: 'password',
            private_type: :password,
            protocol: 'tcp',
            service_name: 'http',
            status: Metasploit::Model::Login::Status::UNTRIED,
            username: 'user',
            workspace_id: workspace.id
          }
        )
        expect(aux_prometheus).to receive(:print_good).with("Credentials\n===========\n\n  Name        Config                 Host       Port  Public/Username  Private/Password/Token  Notes\n  ----        ------                 ----       ----  ---------------  ----------------------  -----\n  prometheus  static_configs Target  localhost  9090  user             password\n  prometheus  static_configs Target  localhost  80    user             password\n")

        aux_prometheus.prometheus_config_eater(
          config_wrapper(
            [
              {
                'job_name' => 'prometheus',
                'static_configs' => [
                  {
                    'targets' => [
                      'https://user:password@localhost:9090',
                      'http://user:password@localhost',
                      'localhost:9191'
                    ]
                  }
                ]
              }
            ]
          )
        )
      end
    end

    context 'prometheus_config_eater correctly processes dns_sd_configs' do
      before(:example) do
        expect(aux_prometheus).to receive(:myworkspace).at_least(:once).and_return(workspace)
      end

      it 'stores creds and prints a table' do
        expect(aux_prometheus).to receive(:create_credential_and_login).with(
          {
            address: 'first.dns.address.domain.com',
            module_fullname: 'auxiliary/gather/prometheus',
            origin_type: :service,
            port: 443,
            private_data: "multiline\nmysecret\ntest",
            private_type: :password,
            protocol: 'tcp',
            service_name: 'https',
            status: Metasploit::Model::Login::Status::UNTRIED,
            username: 'admin_name',
            workspace_id: workspace.id
          }
        )
        expect(aux_prometheus).to receive(:create_credential_and_login).with(
          {
            address: 'second.dns.address.domain.com',
            module_fullname: 'auxiliary/gather/prometheus',
            origin_type: :service,
            port: 443,
            private_data: "multiline\nmysecret\ntest",
            private_type: :password,
            protocol: 'tcp',
            service_name: 'https',
            status: Metasploit::Model::Login::Status::UNTRIED,
            username: 'admin_name',
            workspace_id: workspace.id
          }
        )
        expect(aux_prometheus).to receive(:create_credential_and_login).with(
          {
            address: 'first.dns.address.domain.com',
            module_fullname: 'auxiliary/gather/prometheus',
            origin_type: :service,
            port: 443,
            private_data: "multiline\nmysecret\ntest",
            private_type: :password,
            protocol: 'tcp',
            service_name: 'https',
            status: Metasploit::Model::Login::Status::UNTRIED,
            username: 'admin_name',
            workspace_id: workspace.id
          }
        )
        expect(aux_prometheus).to receive(:print_good).with("Credentials\n===========\n\n  Name       Config          Host                           Port  Public/Username  Private/Password/Token   Notes\n  ----       ------          ----                           ----  ---------------  ----------------------   -----\n  service-x  dns_sd_configs  first.dns.address.domain.com   443   admin_name       multiline\nmysecret\ntest\n  service-x  dns_sd_configs  second.dns.address.domain.com  443   admin_name       multiline\nmysecret\ntest\n  service-x  dns_sd_configs  first.dns.address.domain.com   443   admin_name       multiline\nmysecret\ntest\n")

        aux_prometheus.prometheus_config_eater(
          config_wrapper(
            [
              {
                'job_name' => 'service-x',
                'basic_auth' => {
                  'username' => 'admin_name',
                  'password' => "multiline\nmysecret\ntest"
                },
                'scrape_interval' => '50s',
                'scrape_timeout' => '5s',
                'body_size_limit' => '10MB',
                'sample_limit' => 1000,
                'target_limit' => 35,
                'label_limit' => 35,
                'label_name_length_limit' => 210,
                'label_value_length_limit' => 210,
                'metrics_path' => '/my_path',
                'scheme' => 'https',
                'dns_sd_configs' => [
                  {
                    'refresh_interval' => '15s',
                    'names' => [
                      'first.dns.address.domain.com',
                      'second.dns.address.domain.com'
                    ]
                  },
                  {
                    'names' => [
                      'first.dns.address.domain.com'
                    ]
                  }
                ]
              }
            ]
          )
        )
      end
    end

    context 'prometheus_config_eater correctly processes consul_sd_configs' do
      before(:example) do
        expect(aux_prometheus).to receive(:myworkspace).at_least(:once).and_return(workspace)
      end

      it 'stores creds and prints a table' do
        expect(aux_prometheus).to receive(:create_credential_and_login).with(
          {
            address: 'localhost',
            module_fullname: 'auxiliary/gather/prometheus',
            origin_type: :service,
            port: 1234,
            private_data: 'mysecret',
            private_type: :password,
            protocol: 'tcp',
            service_name: 'https',
            status: Metasploit::Model::Login::Status::UNTRIED,
            username: '',
            workspace_id: workspace.id
          }
        )
        expect(aux_prometheus).to receive(:print_good).with("Credentials\n===========\n\n  Name       Config             Host       Port  Public/Username  Private/Password/Token  Notes\n  ----       ------             ----       ----  ---------------  ----------------------  -----\n  service-y  consul_sd_configs  localhost  1234                   mysecret                Path Prefix: /consul\n")

        aux_prometheus.prometheus_config_eater(
          config_wrapper(
            [
              {
                'job_name' => 'service-y',
                'consul_sd_configs' => [
                  {
                    'server' => 'localhost:1234',
                    'token' => 'mysecret',
                    'path_prefix' => '/consul',
                    'services' => [
                      'nginx',
                      'cache',
                      'mysql'
                    ],
                    'tags' => [
                      'canary',
                      'v1'
                    ],
                    'node_meta' => {
                      'rack' => '123'
                    },
                    'allow_stale' => true,
                    'scheme' => 'https',
                    'tls_config' => {
                      'ca_file' => 'valid_ca_file',
                      'cert_file' => 'valid_cert_file',
                      'key_file' => 'valid_key_file',
                      'insecure_skip_verify' => false
                    }
                  }
                ]
              }
            ]
          )
        )
      end
    end

    context 'prometheus_config_eater correctly processes authorization' do
      before(:example) do
        expect(aux_prometheus).to receive(:myworkspace).at_least(:once).and_return(workspace)
      end

      it 'stores creds and prints a table' do
        expect(aux_prometheus).to receive(:create_credential_and_login).with(
          {
            address: '',
            module_fullname: 'auxiliary/gather/prometheus',
            origin_type: :service,
            port: '',
            private_data: 'mysecret',
            private_type: :password,
            protocol: 'tcp',
            service_name: '',
            status: Metasploit::Model::Login::Status::UNTRIED,
            username: '',
            workspace_id: workspace.id
          }
        )
        expect(aux_prometheus).to receive(:print_good).with("Credentials\n===========\n\n  Name       Config         Host  Port  Public/Username  Private/Password/Token  Notes\n  ----       ------         ----  ----  ---------------  ----------------------  -----\n  service-z  authorization                               mysecret\n")

        aux_prometheus.prometheus_config_eater(
          config_wrapper(
            [
              {
                'job_name' => 'service-z',
                'tls_config' => {
                  'cert_file' => 'valid_cert_file',
                  'key_file' => 'valid_key_file'
                },
                'authorization' => {
                  'credentials' => 'mysecret'
                }
              },
            ]
          )
        )
      end
    end

    context 'prometheus_config_eater correctly processes kubernetes_sd_configs creds in array' do
      before(:example) do
        expect(aux_prometheus).to receive(:myworkspace).at_least(:once).and_return(workspace)
      end

      it 'stores creds and prints a table' do
        expect(aux_prometheus).to receive(:create_credential_and_login).with(
          {
            address: 'localhost',
            module_fullname: 'auxiliary/gather/prometheus',
            origin_type: :service,
            port: 1234,
            private_data: 'mysecret',
            private_type: :password,
            protocol: 'tcp',
            service_name: 'https',
            status: Metasploit::Model::Login::Status::UNTRIED,
            username: 'myusername',
            workspace_id: workspace.id
          }
        )
        expect(aux_prometheus).to receive(:print_good).with("Credentials\n===========\n\n  Name                Config                 Host       Port  Public/Username  Private/Password/Token  Notes\n  ----                ------                 ----       ----  ---------------  ----------------------  -----\n  service-kubernetes  kubernetes_sd_configs  localhost  1234  myusername       mysecret                Role: endpoints\n")

        aux_prometheus.prometheus_config_eater(
          config_wrapper(
            [
              {
                'job_name' => 'service-kubernetes',
                'kubernetes_sd_configs' => [
                  {
                    'role' => 'endpoints',
                    'api_server' => 'https://localhost:1234',
                    'tls_config' => {
                      'cert_file' => 'valid_cert_file',
                      'key_file' => 'valid_key_file'
                    },
                    'basic_auth' => {
                      'username' => 'myusername',
                      'password' => 'mysecret'
                    }
                  }
                ]
              },
            ]
          )
        )
      end
    end

    context 'prometheus_config_eater correctly processes kubernetes_sd_configs creds outside array' do
      before(:example) do
        expect(aux_prometheus).to receive(:myworkspace).at_least(:once).and_return(workspace)
      end

      it 'stores creds and prints a table' do
        expect(aux_prometheus).to receive(:create_credential_and_login).with(
          {
            address: 'localhost',
            module_fullname: 'auxiliary/gather/prometheus',
            origin_type: :service,
            port: 1234,
            private_data: 'valid_password_file',
            private_type: :password,
            protocol: 'tcp',
            service_name: 'https',
            status: Metasploit::Model::Login::Status::UNTRIED,
            username: 'myusername',
            workspace_id: workspace.id
          }
        )
        expect(aux_prometheus).to receive(:print_good).with("Credentials\n===========\n\n  Name                           Config                 Host       Port  Public/Username  Private/Password/Token  Notes\n  ----                           ------                 ----       ----  ---------------  ----------------------  -----\n  service-kubernetes-namespaces  kubernetes_sd_configs  localhost  1234  myusername       valid_password_file     Role: endpoints\n")

        aux_prometheus.prometheus_config_eater(
          config_wrapper(
            [
              {
                'job_name' => 'service-kubernetes-namespaces',
                'kubernetes_sd_configs' => [
                  {
                    'role' => 'endpoints',
                    'api_server' => 'https://localhost:1234',
                    'namespaces' => {
                      'names' => [
                        'default'
                      ]
                    }
                  }
                ],
                'basic_auth' => {
                  'username' => 'myusername',
                  'password_file' => 'valid_password_file'
                }
              },
            ]
          )
        )
      end
    end

    context 'prometheus_config_eater correctly processes kuma_sd_configs' do
      before(:example) do
        expect(aux_prometheus).to receive(:myworkspace).at_least(:once).and_return(workspace)
      end

      it 'stores creds and prints a table' do
        expect(aux_prometheus).to receive(:create_credential_and_login).with(
          {
            address: 'kuma-control-plane.kuma-system.svc',
            module_fullname: 'auxiliary/gather/prometheus',
            origin_type: :service,
            port: 5676,
            private_data: 'password',
            private_type: :password,
            protocol: 'tcp',
            service_name: 'http',
            status: Metasploit::Model::Login::Status::UNTRIED,
            username: 'username',
            workspace_id: workspace.id
          }
        )
        expect(aux_prometheus).to receive(:print_good).with("Credentials\n===========\n\n  Name          Config           Host                                Port  Public/Username  Private/Password/Token  Notes\n  ----          ------           ----                                ----  ---------------  ----------------------  -----\n  service-kuma  kuma_sd_configs  kuma-control-plane.kuma-system.svc  5676  username         password\n")

        aux_prometheus.prometheus_config_eater(
          config_wrapper(
            [
              {
                'job_name' => 'service-kuma',
                'kuma_sd_configs' => [
                  {
                    'server' => 'http://kuma-control-plane.kuma-system.svc:5676'
                  },
                  {
                    'server' => 'http://username:password@kuma-control-plane.kuma-system.svc:5676'
                  }
                ]
              },
            ]
          )
        )
      end
    end

    context 'prometheus_config_eater correctly processes service-marathon' do
      before(:example) do
        expect(aux_prometheus).to receive(:myworkspace).at_least(:once).and_return(workspace)
      end

      it 'stores creds and prints a table' do
        expect(aux_prometheus).to receive(:create_credential_and_login).with(
          {
            address: 'marathon.example.com',
            module_fullname: 'auxiliary/gather/prometheus',
            origin_type: :service,
            port: 443,
            private_data: 'mysecret',
            private_type: :password,
            protocol: 'tcp',
            service_name: 'https',
            status: Metasploit::Model::Login::Status::UNTRIED,
            username: '',
            workspace_id: workspace.id
          }
        )
        expect(aux_prometheus).to receive(:print_good).with("Credentials\n===========\n\n  Name              Config               Host                  Port  Public/Username  Private/Password/Token  Notes\n  ----              ------               ----                  ----  ---------------  ----------------------  -----\n  service-marathon  marathon_sd_configs  marathon.example.com  443                    mysecret\n")

        aux_prometheus.prometheus_config_eater(
          config_wrapper(
            [
              {
                'job_name' => 'service-marathon',
                'marathon_sd_configs' => [
                  {
                    'servers' => [
                      'https://marathon.example.com:443'
                    ],
                    'auth_token' => 'mysecret',
                    'tls_config' => {
                      'cert_file' => 'valid_cert_file',
                      'key_file' => 'valid_key_file'
                    }
                  }
                ]
              },
            ]
          )
        )
      end
    end

    context 'prometheus_config_eater correctly processes service-nomad' do
      before(:example) do
        expect(aux_prometheus).to receive(:myworkspace).at_least(:once).and_return(workspace)
      end

      it 'stores creds and prints a table' do
        expect(aux_prometheus).to receive(:create_credential_and_login).with(
          {
            address: 'localhost',
            module_fullname: 'auxiliary/gather/prometheus',
            origin_type: :service,
            port: 4646,
            private_data: 'password',
            private_type: :password,
            protocol: 'tcp',
            service_name: 'http',
            status: Metasploit::Model::Login::Status::UNTRIED,
            username: 'username',
            workspace_id: workspace.id
          }
        )
        expect(aux_prometheus).to receive(:print_good).with("Credentials\n===========\n\n  Name           Config            Host       Port  Public/Username  Private/Password/Token  Notes\n  ----           ------            ----       ----  ---------------  ----------------------  -----\n  service-nomad  nomad_sd_configs  localhost  4646  username         password\n")

        aux_prometheus.prometheus_config_eater(
          config_wrapper(
            [
              {
                'job_name' => 'service-nomad',
                'nomad_sd_configs' => [
                  {
                    'server' => 'http://username:password@localhost:4646'
                  }
                ]
              },
            ]
          )
        )
      end
    end

    context 'prometheus_config_eater correctly processes ec2_sd_configs' do
      before(:example) do
        expect(aux_prometheus).to receive(:myworkspace).at_least(:once).and_return(workspace)
      end

      it 'stores creds and prints a table' do
        expect(aux_prometheus).to receive(:create_credential_and_login).with(
          {
            address: '',
            module_fullname: 'auxiliary/gather/prometheus',
            origin_type: :service,
            port: '',
            private_data: 'mysecret',
            private_type: :password,
            protocol: 'tcp',
            service_name: '',
            status: Metasploit::Model::Login::Status::UNTRIED,
            username: 'access',
            workspace_id: workspace.id
          }
        )
        expect(aux_prometheus).to receive(:print_good).with("Credentials\n===========\n\n  Name         Config          Host  Port  Public/Username  Private/Password/Token  Notes\n  ----         ------          ----  ----  ---------------  ----------------------  -----\n  service-ec2  ec2_sd_configs              access           mysecret                Region: us-east-1, Profile: profile\n")

        aux_prometheus.prometheus_config_eater(
          config_wrapper(
            [
              {
                'job_name' => 'service-ec2',
                'ec2_sd_configs' => [
                  {
                    'region' => 'us-east-1',
                    'access_key' => 'access',
                    'secret_key' => 'mysecret',
                    'profile' => 'profile'
                  }
                ]
              },
            ]
          )
        )
      end
    end

    context 'prometheus_config_eater correctly processes lightsail_sd_configs' do
      before(:example) do
        expect(aux_prometheus).to receive(:myworkspace).at_least(:once).and_return(workspace)
      end

      it 'stores creds and prints a table' do
        expect(aux_prometheus).to receive(:create_credential_and_login).with(
          {
            address: '',
            module_fullname: 'auxiliary/gather/prometheus',
            origin_type: :service,
            port: '',
            private_data: 'mysecret',
            private_type: :password,
            protocol: 'tcp',
            service_name: '',
            status: Metasploit::Model::Login::Status::UNTRIED,
            username: 'access',
            workspace_id: workspace.id
          }
        )
        expect(aux_prometheus).to receive(:print_good).with("Credentials\n===========\n\n  Name               Config                Host  Port  Public/Username  Private/Password/Token  Notes\n  ----               ------                ----  ----  ---------------  ----------------------  -----\n  service-lightsail  lightsail_sd_configs              access           mysecret                Region: us-east-1, Profile: profile\n")

        aux_prometheus.prometheus_config_eater(
          config_wrapper(
            [
              {
                'job_name' => 'service-lightsail',
                'lightsail_sd_configs' => [
                  {
                    'region' => 'us-east-1',
                    'access_key' => 'access',
                    'secret_key' => 'mysecret',
                    'profile' => 'profile'
                  }
                ]
              },
            ]
          )
        )
      end
    end

    context 'prometheus_config_eater correctly processes service-azure' do
      before(:example) do
        expect(aux_prometheus).to receive(:myworkspace).at_least(:once).and_return(workspace)
      end

      it 'stores creds and prints a table' do
        expect(aux_prometheus).to receive(:create_credential_and_login).with(
          {
            address: '',
            module_fullname: 'auxiliary/gather/prometheus',
            origin_type: :service,
            port: 9100,
            private_data: 'mysecret',
            private_type: :password,
            protocol: 'tcp',
            service_name: 'OAuth',
            status: Metasploit::Model::Login::Status::UNTRIED,
            username: '333333CC-3C33-3333-CCC3-33C3CCCCC33C',
            workspace_id: workspace.id
          }
        )
        expect(aux_prometheus).to receive(:print_good).with("Credentials\n===========\n\n  Name           Config            Host  Port  Public/Username                       Private/Password/Token  Notes\n  ----           ------            ----  ----  ---------------                       ----------------------  -----\n  service-azure  azure_sd_configs        9100  333333CC-3C33-3333-CCC3-33C3CCCCC33C  mysecret                Environment: AzurePublicCloud, Subscription ID: 11AAAA11-A11A-111A-A111-1111A1111A11, Resource Group: my-resource-group, Tenant ID: BBBB222B-B2B2-2B22-B222-2BB2222BB2B2\n")

        aux_prometheus.prometheus_config_eater(
          config_wrapper(
            [
              {
                'job_name' => 'service-azure',
                'azure_sd_configs' => [
                  {
                    'environment' => 'AzurePublicCloud',
                    'authentication_method' => 'OAuth',
                    'subscription_id' => '11AAAA11-A11A-111A-A111-1111A1111A11',
                    'resource_group' => 'my-resource-group',
                    'tenant_id' => 'BBBB222B-B2B2-2B22-B222-2BB2222BB2B2',
                    'client_id' => '333333CC-3C33-3333-CCC3-33C3CCCCC33C',
                    'client_secret' => 'mysecret',
                    'port' => 9100
                  }
                ]
              },
            ]
          )
        )
      end
    end

    context 'prometheus_config_eater correctly processes http_sd_configs' do
      before(:example) do
        expect(aux_prometheus).to receive(:myworkspace).at_least(:once).and_return(workspace)
      end

      it 'stores creds and prints a table' do
        expect(aux_prometheus).to receive(:create_credential_and_login).with(
          {
            address: 'example1.com',
            module_fullname: 'auxiliary/gather/prometheus',
            origin_type: :service,
            port: 80,
            private_data: 'password',
            private_type: :password,
            protocol: 'tcp',
            service_name: 'http',
            status: Metasploit::Model::Login::Status::UNTRIED,
            username: 'username',
            workspace_id: workspace.id
          }
        )
        expect(aux_prometheus).to receive(:print_good).with("Credentials\n===========\n\n  Name    Config           Host          Port  Public/Username  Private/Password/Token  Notes\n  ----    ------           ----          ----  ---------------  ----------------------  -----\n  httpsd  http_sd_configs  example1.com  80    username         password\n")

        aux_prometheus.prometheus_config_eater(
          config_wrapper(
            [
              {
                'job_name' => 'httpsd',
                'http_sd_configs' => [
                  {
                    'url' => 'http://example2.com/prometheus'
                  },
                  {
                    'url' => 'http://username:password@example1.com/prometheus'
                  }
                ]
              },
            ]
          )
        )
      end
    end

    context 'prometheus_config_eater correctly processes digitalocean_sd_configs' do
      before(:example) do
        expect(aux_prometheus).to receive(:myworkspace).at_least(:once).and_return(workspace)
      end

      it 'stores creds and prints a table' do
        expect(aux_prometheus).to receive(:create_credential_and_login).with(
          {
            address: '',
            module_fullname: 'auxiliary/gather/prometheus',
            origin_type: :service,
            port: '',
            private_data: 'abcdef',
            private_type: :password,
            protocol: 'tcp',
            service_name: '',
            status: Metasploit::Model::Login::Status::UNTRIED,
            username: '',
            workspace_id: workspace.id
          }
        )
        expect(aux_prometheus).to receive(:print_good).with("Credentials\n===========\n\n  Name                   Config                   Host  Port  Public/Username  Private/Password/Token  Notes\n  ----                   ------                   ----  ----  ---------------  ----------------------  -----\n  digitalocean-droplets  digitalocean_sd_configs                               abcdef\n")

        aux_prometheus.prometheus_config_eater(
          config_wrapper(
            [
              {
                'job_name' => 'digitalocean-droplets',
                'digitalocean_sd_configs' => [
                  {
                    'authorization' => {
                      'credentials' => 'abcdef'
                    }
                  }
                ]
              },
            ]
          )
        )
      end
    end

    context 'prometheus_config_eater correctly processes hetzner_sd_configs with authorization' do
      before(:example) do
        expect(aux_prometheus).to receive(:myworkspace).at_least(:once).and_return(workspace)
      end

      it 'stores creds and prints a table' do
        expect(aux_prometheus).to receive(:create_credential_and_login).with(
          {
            address: '',
            module_fullname: 'auxiliary/gather/prometheus',
            origin_type: :service,
            port: '',
            private_data: 'abcdef',
            private_type: :password,
            protocol: 'tcp',
            service_name: '',
            status: Metasploit::Model::Login::Status::UNTRIED,
            username: '',
            workspace_id: workspace.id
          }
        )
        expect(aux_prometheus).to receive(:print_good).with("Credentials\n===========\n\n  Name     Config              Host  Port  Public/Username  Private/Password/Token  Notes\n  ----     ------              ----  ----  ---------------  ----------------------  -----\n  hetzner  hetzner_sd_configs                               abcdef                  hcloud\n")

        aux_prometheus.prometheus_config_eater(
          config_wrapper(
            [
              {
                'job_name' => 'hetzner',
                'hetzner_sd_configs' => [
                  {
                    'role' => 'hcloud',
                    'authorization' => {
                      'credentials' => 'abcdef'
                    }
                  }

                ]
              },
            ]
          )
        )
      end
    end

    context 'prometheus_config_eater correctly processes hetzner_sd_configs with basic_auth' do
      before(:example) do
        expect(aux_prometheus).to receive(:myworkspace).at_least(:once).and_return(workspace)
      end

      it 'stores creds and prints a table' do
        expect(aux_prometheus).to receive(:create_credential_and_login).with(
          {
            address: '',
            module_fullname: 'auxiliary/gather/prometheus',
            origin_type: :service,
            port: '',
            private_data: 'abcdef',
            private_type: :password,
            protocol: 'tcp',
            service_name: '',
            status: Metasploit::Model::Login::Status::UNTRIED,
            username: 'abcdef',
            workspace_id: workspace.id
          }
        )
        expect(aux_prometheus).to receive(:print_good).with("Credentials\n===========\n\n  Name     Config              Host  Port  Public/Username  Private/Password/Token  Notes\n  ----     ------              ----  ----  ---------------  ----------------------  -----\n  hetzner  hetzner_sd_configs              abcdef           abcdef                  robot\n")

        aux_prometheus.prometheus_config_eater(
          config_wrapper(
            [
              {
                'job_name' => 'hetzner',
                'hetzner_sd_configs' => [
                  {
                    'role' => 'robot',
                    'basic_auth' => {
                      'username' => 'abcdef',
                      'password' => 'abcdef'
                    }
                  }
                ]
              },
            ]
          )
        )
      end
    end

    context 'prometheus_config_eater correctly processes eureka_sd_configs' do
      before(:example) do
        expect(aux_prometheus).to receive(:myworkspace).at_least(:once).and_return(workspace)
      end

      it 'stores creds and prints a table' do
        expect(aux_prometheus).to receive(:create_credential_and_login).with(
          {
            address: 'eureka.example.com',
            module_fullname: 'auxiliary/gather/prometheus',
            origin_type: :service,
            port: 8761,
            private_data: 'password',
            private_type: :password,
            protocol: 'tcp',
            service_name: 'http',
            status: Metasploit::Model::Login::Status::UNTRIED,
            username: 'username',
            workspace_id: workspace.id
          }
        )
        expect(aux_prometheus).to receive(:print_good).with("Credentials\n===========\n\n  Name            Config             Host                Port  Public/Username  Private/Password/Token  Notes\n  ----            ------             ----                ----  ---------------  ----------------------  -----\n  service-eureka  eureka_sd_configs  eureka.example.com  8761  username         password\n")

        aux_prometheus.prometheus_config_eater(
          config_wrapper(
            [
              {
                'job_name' => 'service-eureka',
                'eureka_sd_configs' => [
                  {
                    'server' => 'http://username:password@eureka.example.com:8761/eureka'
                  }
                ]
              },
            ]
          )
        )
      end
    end

    context 'prometheus_config_eater correctly processes ovhcloud_sd_configs' do
      before(:example) do
        expect(aux_prometheus).to receive(:myworkspace).at_least(:once).and_return(workspace)
      end

      it 'stores creds and prints a table' do
        expect(aux_prometheus).to receive(:create_credential_and_login).with(
          {
            address: 'ovh-eu',
            module_fullname: 'auxiliary/gather/prometheus',
            origin_type: :service,
            port: '',
            private_data: 'testAppSecret',
            private_type: :password,
            protocol: 'tcp',
            service_name: 'vps',
            status: Metasploit::Model::Login::Status::UNTRIED,
            username: 'testAppKey',
            workspace_id: workspace.id
          }
        )

        expect(aux_prometheus).to receive(:create_credential_and_login).with(
          {
            address: 'ovh-eu',
            module_fullname: 'auxiliary/gather/prometheus',
            origin_type: :service,
            port: '',
            private_data: 'testAppSecret',
            private_type: :password,
            protocol: 'tcp',
            service_name: 'dedicated_server',
            status: Metasploit::Model::Login::Status::UNTRIED,
            username: 'testAppKey',
            workspace_id: workspace.id
          }
        )
        expect(aux_prometheus).to receive(:print_good).with("Credentials\n===========\n\n  Name      Config               Host    Port  Public/Username  Private/Password/Token  Notes\n  ----      ------               ----    ----  ---------------  ----------------------  -----\n  ovhcloud  ovhcloud_sd_configs  ovh-eu        testAppKey       testAppSecret           Consumer Key: testConsumerKey, Service: vps\n  ovhcloud  ovhcloud_sd_configs  ovh-eu        testAppKey       testAppSecret           Consumer Key: testConsumerKey, Service: dedicated_server\n")

        aux_prometheus.prometheus_config_eater(
          config_wrapper(
            [
              {
                'job_name' => 'ovhcloud',
                'ovhcloud_sd_configs' => [
                  {
                    'service' => 'vps',
                    'endpoint' => 'ovh-eu',
                    'application_key' => 'testAppKey',
                    'application_secret' => 'testAppSecret',
                    'consumer_key' => 'testConsumerKey',
                    'refresh_interval' => '1m'
                  },
                  {
                    'service' => 'dedicated_server',
                    'endpoint' => 'ovh-eu',
                    'application_key' => 'testAppKey',
                    'application_secret' => 'testAppSecret',
                    'consumer_key' => 'testConsumerKey',
                    'refresh_interval' => '1m'
                  }
                ]
              },
            ]
          )
        )
      end
    end

    context 'prometheus_config_eater correctly processes scaleway_sd_configs' do
      before(:example) do
        expect(aux_prometheus).to receive(:myworkspace).at_least(:once).and_return(workspace)
      end

      it 'stores creds and prints a table' do
        expect(aux_prometheus).to receive(:create_credential_and_login).with(
          {
            address: '',
            module_fullname: 'auxiliary/gather/prometheus',
            origin_type: :service,
            port: '',
            private_data: '11111111-1111-1111-1111-111111111111',
            private_type: :password,
            protocol: 'tcp',
            service_name: 'instance',
            status: Metasploit::Model::Login::Status::UNTRIED,
            username: 'SCWXXXXXXXXXXXXXXXXX',
            workspace_id: workspace.id
          }
        )

        expect(aux_prometheus).to receive(:create_credential_and_login).with(
          {
            address: '',
            module_fullname: 'auxiliary/gather/prometheus',
            origin_type: :service,
            port: '',
            private_data: '11111111-1111-1111-1111-111111111111',
            private_type: :password,
            protocol: 'tcp',
            service_name: 'baremetal',
            status: Metasploit::Model::Login::Status::UNTRIED,
            username: 'SCWXXXXXXXXXXXXXXXXX',
            workspace_id: workspace.id
          }
        )
        expect(aux_prometheus).to receive(:print_good).with("Credentials\n===========\n\n  Name      Config               Host  Port  Public/Username       Private/Password/Token                Notes\n  ----      ------               ----  ----  ---------------       ----------------------                -----\n  scaleway  scaleway_sd_configs              SCWXXXXXXXXXXXXXXXXX  11111111-1111-1111-1111-111111111111  Project ID: 11111111-1111-1111-1111-111111111112, Role: instance\n  scaleway  scaleway_sd_configs              SCWXXXXXXXXXXXXXXXXX  11111111-1111-1111-1111-111111111111  Project ID: 11111111-1111-1111-1111-111111111112, Role: baremetal\n")

        aux_prometheus.prometheus_config_eater(
          config_wrapper(
            [
              {
                'job_name' => 'scaleway',
                'scaleway_sd_configs' => [
                  {
                    'role' => 'instance',
                    'project_id' => '11111111-1111-1111-1111-111111111112',
                    'access_key' => 'SCWXXXXXXXXXXXXXXXXX',
                    'secret_key' => '11111111-1111-1111-1111-111111111111'
                  },
                  {
                    'role' => 'baremetal',
                    'project_id' => '11111111-1111-1111-1111-111111111112',
                    'access_key' => 'SCWXXXXXXXXXXXXXXXXX',
                    'secret_key' => '11111111-1111-1111-1111-111111111111'
                  }
                ]
              },
            ]
          )
        )
      end
    end

    context 'prometheus_config_eater correctly processes linode_sd_configs' do
      before(:example) do
        expect(aux_prometheus).to receive(:myworkspace).at_least(:once).and_return(workspace)
      end

      it 'stores creds and prints a table' do
        expect(aux_prometheus).to receive(:create_credential_and_login).with(
          {
            address: '',
            module_fullname: 'auxiliary/gather/prometheus',
            origin_type: :service,
            port: '',
            private_data: 'abcdef',
            private_type: :password,
            protocol: 'tcp',
            service_name: '',
            status: Metasploit::Model::Login::Status::UNTRIED,
            username: '',
            workspace_id: workspace.id
          }
        )
        expect(aux_prometheus).to receive(:print_good).with("Credentials\n===========\n\n  Name              Config             Host  Port  Public/Username  Private/Password/Token  Notes\n  ----              ------             ----  ----  ---------------  ----------------------  -----\n  linode-instances  linode_sd_configs                               abcdef\n")

        aux_prometheus.prometheus_config_eater(
          config_wrapper(
            [
              {
                'job_name' => 'linode-instances',
                'linode_sd_configs' => [
                  {
                    'authorization' => {
                      'credentials' => 'abcdef'
                    }
                  }
                ]
              },
            ]
          )
        )
      end
    end

    context 'prometheus_config_eater correctly processes uyuni_sd_configs' do
      before(:example) do
        expect(aux_prometheus).to receive(:myworkspace).at_least(:once).and_return(workspace)
      end

      it 'stores creds and prints a table' do
        expect(aux_prometheus).to receive(:create_credential_and_login).with(
          {
            address: 'localhost',
            module_fullname: 'auxiliary/gather/prometheus',
            origin_type: :service,
            port: 1234,
            private_data: 'hole',
            private_type: :password,
            protocol: 'tcp',
            service_name: 'https',
            status: Metasploit::Model::Login::Status::UNTRIED,
            username: 'gopher',
            workspace_id: workspace.id
          }
        )
        expect(aux_prometheus).to receive(:print_good).with("Credentials\n===========\n\n  Name   Config            Host       Port  Public/Username  Private/Password/Token  Notes\n  ----   ------            ----       ----  ---------------  ----------------------  -----\n  uyuni  uyuni_sd_configs  localhost  1234  gopher           hole\n")

        aux_prometheus.prometheus_config_eater(
          config_wrapper(
            [
              {
                'job_name' => 'uyuni',
                'uyuni_sd_configs' => [
                  {
                    'server' => 'https://localhost:1234',
                    'username' => 'gopher',
                    'password' => 'hole'
                  }
                ]
              },
            ]
          )
        )
      end
    end

    context 'prometheus_config_eater correctly processes ionos_sd_configs' do
      before(:example) do
        expect(aux_prometheus).to receive(:myworkspace).at_least(:once).and_return(workspace)
      end

      it 'stores creds and prints a table' do
        expect(aux_prometheus).to receive(:create_credential_and_login).with(
          {
            address: '',
            module_fullname: 'auxiliary/gather/prometheus',
            origin_type: :service,
            port: '',
            private_data: 'abcdef',
            private_type: :password,
            protocol: 'tcp',
            service_name: '',
            status: Metasploit::Model::Login::Status::UNTRIED,
            username: '8feda53f-15f0-447f-badf-ebe32dad2fc0',
            workspace_id: workspace.id
          }
        )
        expect(aux_prometheus).to receive(:print_good).with("Credentials\n===========\n\n  Name   Config            Host  Port  Public/Username                       Private/Password/Token  Notes\n  ----   ------            ----  ----  ---------------                       ----------------------  -----\n  ionos  ionos_sd_configs              8feda53f-15f0-447f-badf-ebe32dad2fc0  abcdef\n")

        aux_prometheus.prometheus_config_eater(
          config_wrapper(
            [
              {
                'job_name' => 'ionos',
                'ionos_sd_configs' => [
                  {
                    'datacenter_id' => '8feda53f-15f0-447f-badf-ebe32dad2fc0',
                    'authorization' => {
                      'credentials' => 'abcdef'
                    }
                  }
                ]
              },
            ]
          )
        )
      end
    end

    context 'prometheus_config_eater correctly processes vultr_sd_configs' do
      before(:example) do
        expect(aux_prometheus).to receive(:myworkspace).at_least(:once).and_return(workspace)
      end

      it 'stores creds and prints a table' do
        expect(aux_prometheus).to receive(:create_credential_and_login).with(
          {
            address: '',
            module_fullname: 'auxiliary/gather/prometheus',
            origin_type: :service,
            port: '',
            private_data: 'abcdef',
            private_type: :password,
            protocol: 'tcp',
            service_name: '',
            status: Metasploit::Model::Login::Status::UNTRIED,
            username: '',
            workspace_id: workspace.id
          }
        )
        expect(aux_prometheus).to receive(:print_good).with("Credentials\n===========\n\n  Name   Config            Host  Port  Public/Username  Private/Password/Token  Notes\n  ----   ------            ----  ----  ---------------  ----------------------  -----\n  vultr  vultr_sd_configs                               abcdef\n")

        aux_prometheus.prometheus_config_eater(
          config_wrapper(
            [
              {
                'job_name' => 'vultr',
                'vultr_sd_configs' => [
                  {
                    'authorization' => {
                      'credentials' => 'abcdef'
                    }
                  }
                ]
              }
            ]
          )
        )
      end
    end
  end
end
