require 'spec_helper'
require 'rack/test'
require 'rack/protection'

# These tests ensure the full end to end functionality of metasploit's JSON RPC
# endpoint. There are multiple layers of possible failure in our API, and unit testing
# alone will not cover all edge cases. For instance, middleware may raise exceptions
# and return HTML to the calling client unintentionally - which will break our JSON
# response contract. These test should help catch such scenarios.
RSpec.describe "Metasploit's json-rpc" do
  include Rack::Test::Methods
  include_context 'Msf::DBManager'
  include_context 'Metasploit::Framework::Spec::Constants cleaner'
  include_context 'Msf::Framework#threads cleaner', verify_cleanup_required: false

  let(:health_check_url) { '/api/v1/health' }
  let(:rpc_url) { '/api/v1/json-rpc' }
  let(:module_name) { 'scanner/ssl/openssl_heartbleed' }
  let(:a_valid_result_uuid) { { result: hash_including({ uuid: match(/\w+/) }) } }
  let(:app) { ::Msf::WebServices::JsonRpcApp.new }

  before(:example) do
    framework.modules.add_module_path(File.join(FILE_FIXTURES_PATH, 'json_rpc'))
    app.settings.framework = framework
  end

  after(:example) do
    # Sinatra's settings are implemented as a singleton, and must be explicitly reset between runs
    app.settings.dispatchers.clear
  end

  def report_host(host)
    post rpc_url, {
      jsonrpc: '2.0',
      method: 'db.report_host',
      id: 1,
      params: [
        host
      ]
    }.to_json
  end

  def report_vuln(vuln)
    post rpc_url, {
      jsonrpc: '2.0',
      method: 'db.report_vuln',
      id: 1,
      params: [
        vuln
      ]
    }.to_json
  end

  def analyze_host(host)
    post rpc_url, {
      jsonrpc: '2.0',
      method: 'db.analyze_host',
      id: 1,
      params: [
        host
      ]
    }.to_json
  end

  def create_job
    post rpc_url, {
      jsonrpc: '2.0',
      method: 'module.check',
      id: 1,
      params: [
        'auxiliary',
        module_name,
        {
          RHOSTS: '192.0.2.0'
        }
      ]
    }.to_json
  end

  def get_job_results(uuid)
    post rpc_url, {
      jsonrpc: '2.0',
      method: 'module.results',
      id: 1,
      params: [
        uuid
      ]
    }.to_json
  end

  def get_rpc_health_check
    post rpc_url, {
      jsonrpc: '2.0',
      method: 'health.check',
      id: 1,
      params: []
    }.to_json
  end

  def get_rest_health_check
    get health_check_url
  end

  def last_json_response
    JSON.parse(last_response.body).with_indifferent_access
  end

  def expect_completed_status(rpc_response)
    expect(rpc_response).to include({ result: hash_including({ status: 'completed' }) })
  end

  def expect_error_status(rpc_response)
    expect(rpc_response).to include({ result: hash_including({ status: 'errored' }) })
  end

  def mock_rack_env(mock_rack_env_value)
    allow(ENV).to receive(:[]).and_wrap_original do |original_env, key|
      if key == 'RACK_ENV'
        mock_rack_env_value
      else
        original_env[key]
      end
    end
  end

  # Waits until the given expectations are all true. This function executes the given block,
  # and if a failure occurs it will be retried `retry_count` times before finally failing.
  # This is useful to expect against asynchronous/eventually consistent systems.
  #
  # @param retry_count [Integer] The total amount of times to retry the given expectation
  # @param sleep_duration [Integer] The total amount of time to sleep before trying again
  def wait_for_expect(retry_count = 20, sleep_duration = 0.5)
    failure_count = 0

    begin
      yield
    rescue RSpec::Expectations::ExpectationNotMetError
      failure_count += 1
      if failure_count < retry_count
        sleep sleep_duration
        retry
      else
        raise
      end
    end
  end

  describe 'health status' do
    context 'when using the REST health check functionality' do
      it 'passes the health check' do
        expected_response = {
          data: {
            status: 'UP'
          }
        }

        get_rest_health_check
        expect(last_response).to be_ok
        expect(last_json_response).to include(expected_response)
      end
    end

    context 'when there is an issue' do
      before(:each) do
        allow(framework).to receive(:version).and_raise 'Mock error'
      end

      it 'fails the health check' do
        expected_response = {
          data: {
            status: 'DOWN'
          }
        }

        get_rest_health_check

        expect(last_response.status).to be 503
        expect(last_json_response).to include(expected_response)
      end
    end

    context 'when using the RPC health check functionality' do
      context 'when the service is healthy' do
        it 'passes the health check' do
          expected_response = {
            id: 1,
            jsonrpc: '2.0',
            result: {
              status: 'UP'
            }
          }

          get_rpc_health_check
          expect(last_response).to be_ok
          expect(last_json_response).to include(expected_response)
        end
      end

      context 'when there is an issue' do
        before(:each) do
          allow(framework).to receive(:version).and_raise 'Mock error'
        end

        it 'fails the health check' do
          expected_response = {
            id: 1,
            jsonrpc: '2.0',
            result: {
              status: 'DOWN'
            }
          }

          get_rpc_health_check

          expect(last_response).to be_ok
          expect(last_json_response).to include(expected_response)
        end
      end
    end
  end

  describe 'Running a check job and verifying results' do
    context 'when the module returns check code safe' do
      before(:each) do
        allow_any_instance_of(::Msf::Auxiliary::Scanner).to receive(:check) do
          ::Msf::Exploit::CheckCode::Safe
        end
      end

      it 'returns successful job results' do
        create_job
        expect(last_response).to be_ok
        expect(last_json_response).to include(a_valid_result_uuid)

        uuid = last_json_response['result']['uuid']
        wait_for_expect do
          get_job_results(uuid)

          expect(last_response).to be_ok
          expect_completed_status(last_json_response)
        end

        expected_completed_response = {
          result: {
            status: 'completed',
            result: {
              code: 'safe',
              details: {},
              message: 'The target is not exploitable.',
              reason: nil
            }
          }
        }
        expect(last_json_response).to include(expected_completed_response)
      end
    end

    context 'when the check command raises a known msf error' do
      before(:each) do
        allow_any_instance_of(::Msf::Auxiliary::Scanner).to receive(:check) do |mod|
          mod.fail_with(Msf::Module::Failure::UnexpectedReply, 'Expected failure reason')
        end
      end

      it 'returns the error results' do
        create_job
        expect(last_response).to be_ok
        expect(last_json_response).to include(a_valid_result_uuid)

        uuid = last_json_response['result']['uuid']

        wait_for_expect do
          get_job_results(uuid)

          expect(last_response).to be_ok
          expect_error_status(last_json_response)
        end

        expected_error_response = {
          result: {
            status: 'errored',
            error: 'unexpected-reply: Expected failure reason'
          }
        }
        expect(last_json_response).to include(expected_error_response)
      end
    end

    context 'when the check command has an unexpected error' do
      include_context 'Msf::Framework#threads cleaner'

      before(:each) do
        allow_any_instance_of(::Msf::Auxiliary::Scanner).to receive(:check) do
          res = nil
          res.body
        end
      end

      it 'returns the error results' do
        create_job
        expect(last_response).to be_ok
        expect(last_json_response).to include(a_valid_result_uuid)

        uuid = last_json_response['result']['uuid']

        wait_for_expect do
          get_job_results(uuid)

          expect(last_response).to be_ok
          expect_error_status(last_json_response)
        end

        expected_error_response = {
          result: {
            status: 'errored',
            error: "undefined method `body' for nil:NilClass"
          }
        }
        expect(last_json_response).to include(expected_error_response)
      end
    end

    context 'when there is a sinatra level application error in the development environment' do
      before(:each) do
        allow_any_instance_of(Msf::RPC::JSON::Dispatcher).to receive(:process).and_raise(Exception, 'Sinatra level exception raised')
        mock_rack_env('development')
      end

      it 'returns the error results' do
        create_job

        expect(last_response).to be_server_error
        expected_error_response = {
          error: {
            code: -32000,
            data: {
              backtrace: include(a_kind_of(String))
            },
            message: 'Application server error: Sinatra level exception raised'
          },
          id: 1
        }
        expect(last_json_response).to include(expected_error_response)
      end
    end

    context 'when rack middleware raises an error in the development environment' do
      before(:each) do
        allow_any_instance_of(::Rack::Protection::AuthenticityToken).to receive(:accepts?).and_raise(Exception, 'Middleware error raised')
        mock_rack_env('development')
      end

      it 'returns the error results' do
        create_job

        expect(last_response).to be_server_error
        expected_error_response = {
          error: {
            code: -32000,
            data: {
              backtrace: include(a_kind_of(String))
            },
            message: 'Application server error: Middleware error raised'
          },
          id: 1
        }
        expect(last_json_response).to include(expected_error_response)
      end
    end

    context 'when rack middleware raises an error in the production environment' do
      before(:each) do
        allow_any_instance_of(::Rack::Protection::AuthenticityToken).to receive(:accepts?).and_raise(Exception, 'Middleware error raised')
        mock_rack_env('production')
      end

      it 'returns the error results' do
        create_job

        expect(last_response).to be_server_error
        expected_error_response = {
          error: {
            code: -32000,
            message: 'Application server error: Middleware error raised'
          },
          id: 1
        }
        expect(last_json_response).to include(expected_error_response)
      end
    end

    context 'when there is a sinatra level application error in the production environment' do
      before(:each) do
        allow_any_instance_of(Msf::RPC::JSON::Dispatcher).to receive(:process).and_raise(Exception, 'Sinatra level exception raised')
        mock_rack_env('production')
      end

      it 'returns the error results' do
        create_job

        expect(last_response).to be_server_error
        expected_error_response = {
          error: {
            code: -32000,
            message: 'Application server error: Sinatra level exception raised'
          },
          id: 1
        }
        expect(last_json_response).to include(expected_error_response)
      end
    end
  end

  describe 'analyze' do
    let(:host_ip) { Faker::Internet.private_ip_v4_address }
    let(:host) do
      {
        workspace: 'default',
        host: host_ip,
        state: 'alive',
        os_name: 'Windows',
        os_flavor: 'Enterprize',
        os_sp: 'SP2',
        os_lang: 'English',
        arch: 'ARCH_X86',
        mac: '97-42-51-F2-A7-A7',
        scope: 'eth2',
        virtual_host: 'VMWare'
      }
    end

    let(:vuln) do
      {
        workspace: 'default',
        host: host_ip,
        name: 'Exploit Name',
        info: 'Human readable description of the vuln',
        refs: vuln_refs
      }
    end

    context 'when there are modules available' do
      let(:vuln_refs) do
        %w[
          CVE-2017-0143
        ]
      end

      before(:each) do
        framework.modules.add_module_path('./modules')
      end

      context 'with no options' do
        it 'returns the list of known modules associated with a reported host' do
          report_host(host)
          expect(last_response).to be_ok

          report_vuln(vuln)
          expect(last_response).to be_ok

          expected_response = {
            jsonrpc: '2.0',
            result: {
              host: [
                {
                  address: host_ip,
                  modules: [
                    {
                      mtype: 'exploit',
                      mname: 'exploit/windows/smb/ms17_010_eternalblue'
                    },
                    {
                      mtype: 'exploit',
                      mname: 'exploit/windows/smb/ms17_010_psexec',
                    },
                    {
                      mtype: 'exploit',
                      mname: 'exploit/windows/smb/smb_doublepulsar_rce',
                    }
                  ]
                }
              ]
            },
            id: 1
          }

          analyze_host(
            {
              workspace: 'default',
              host: host_ip
            }
          )
          expect(last_json_response).to include(expected_response)
        end
      end

      context 'when payloads requirements are specified' do
        it 'returns the list of known modules associated with a reported host' do
          report_host(host)
          expect(last_response).to be_ok

          report_vuln(vuln)
          expect(last_response).to be_ok

          # Note: Currently the API doesn't return any differentiating output that a particular module is suitable
          # with the requested payload
          expected_response = {
            jsonrpc: '2.0',
            result: {
              host: [
                {
                  address: host_ip,
                  modules: [
                    {
                      mtype: 'exploit',
                      mname: 'exploit/windows/smb/ms17_010_eternalblue'
                    },
                    {
                      mtype: 'exploit',
                      mname: 'exploit/windows/smb/ms17_010_psexec',
                    },
                    {
                      mtype: 'exploit',
                      mname: 'exploit/windows/smb/smb_doublepulsar_rce',
                    }
                  ]
                }
              ]
            },
            id: 1
          }

          analyze_host(
            {
              workspace: 'default',
              host: host_ip,
              payloads: [
                'java/meterpreter/reverse_http'
              ]
            }
          )
          expect(last_json_response).to include(expected_response)
        end
      end
    end

    context 'when there are no modules found' do
      let(:vuln_refs) do
        ['CVE-NO-MATCHING-MODULES-1234']
      end

      it 'returns an empty list of modules' do
        report_host(host)
        expect(last_response).to be_ok

        report_vuln(vuln)
        expect(last_response).to be_ok

        expected_response = {
          jsonrpc: '2.0',
          result: {
            host: [
              {
                address: host_ip,
                modules: []
              }
            ]
          },
          id: 1
        }

        analyze_host(
          {
            workspace: 'default',
            host: host_ip
          }
        )
        expect(last_json_response).to include(expected_response)
      end
    end
  end
end
