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
  include_context 'wait_for_expect'

  let(:health_check_url) { '/api/v1/health' }
  let(:rpc_url) { '/api/v1/json-rpc' }
  let(:module_name) { 'scanner/ssl/openssl_heartbleed' }
  let(:a_valid_result_uuid) { { result: hash_including({ uuid: match(/\w+/) }) } }
  let(:app) { ::Msf::WebServices::JsonRpcApp.new }

  # Static token used to authenticate all requests in this suite.
  # Using the api_token path avoids needing a real DB user for the non-auth tests.
  let(:suite_token) { 'test_suite_token_abc123' }

  # Sinatra settings are class level, so capture the real values and restore them
  # afterwards rather than resetting to nil, which would discard the environment
  # derived configuration for the remainder of the process.
  let!(:original_api_token) { ::Msf::WebServices::JsonRpcApp.settings.api_token }
  let!(:original_db_manager) { ::Msf::WebServices::JsonRpcApp.settings.db_manager }

  before(:example) do
    framework.modules.add_module_path(File.join(FILE_FIXTURES_PATH, 'json_rpc'))
    app.settings.framework = framework
    # Rack 3 / rack-test requires explicit content type for raw JSON bodies
    header 'Content-Type', 'application/json'

    # Configure auth directly rather than calling boot!, which is covered by its own
    # unit spec. Here we just want the settings in a known state so the HTTP layer
    # behaves as it would in production, with auth enforced via a static token.
    app.settings.api_token = suite_token
    app.settings.db_manager = nil
    header 'Authorization', "Bearer #{suite_token}"
  end

  after(:example) do
    # Sinatra's settings are implemented as a singleton, and must be explicitly reset between runs
    app.settings.dispatchers.clear
    app.settings.api_token = original_api_token
    app.settings.db_manager = original_db_manager
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

  describe 'authentication' do
    context 'when a valid Bearer token is provided' do
      it 'allows the request through' do
        # suite_token header already set by outer before block
        post rpc_url, { jsonrpc: '2.0', method: 'health.check', id: 1, params: [] }.to_json
        expect(last_response.status).not_to eq(401)
      end
    end

    context 'when no token is provided' do
      before { header 'Authorization', nil }

      it 'returns 401' do
        post rpc_url, { jsonrpc: '2.0', method: 'health.check', id: 1, params: [] }.to_json
        expect(last_response.status).to eq(401)
      end

      it 'returns a JSON error body' do
        post rpc_url, { jsonrpc: '2.0', method: 'health.check', id: 1, params: [] }.to_json
        json = JSON.parse(last_response.body)
        expect(json).to have_key('error')
        expect(json['error']['message']).to include('Authenticate to access this resource')
      end
    end

    context 'when an invalid token is provided' do
      before { header 'Authorization', 'Bearer invalid_token' }

      it 'returns 401' do
        post rpc_url, { jsonrpc: '2.0', method: 'health.check', id: 1, params: [] }.to_json
        expect(last_response.status).to eq(401)
      end
    end

    # Query strings end up in access logs, so a token is never accepted from one -
    # not even a correct one.
    context 'when the token is supplied as a query parameter' do
      before { header 'Authorization', nil }

      it 'returns 401 even for the correct token' do
        post "#{rpc_url}?token=#{suite_token}", { jsonrpc: '2.0', method: 'health.check', id: 1, params: [] }.to_json
        expect(last_response.status).to eq(401)
      end

      it 'does not echo the supplied token back in the response' do
        post "#{rpc_url}?token=#{suite_token}", { jsonrpc: '2.0', method: 'health.check', id: 1, params: [] }.to_json
        expect(last_response.body).not_to include(suite_token)
      end
    end

    context 'when the Authorization header uses an unsupported scheme' do
      before { header 'Authorization', "Basic #{suite_token}" }

      it 'returns 401' do
        post rpc_url, { jsonrpc: '2.0', method: 'health.check', id: 1, params: [] }.to_json
        expect(last_response.status).to eq(401)
      end
    end

    # A blank configured token must never match a blank supplied token, otherwise
    # anyone can authenticate with an empty credential.
    context 'when the configured token is blank' do
      before do
        app.settings.api_token = ''
      end

      it 'returns 401 for an empty Bearer token' do
        header 'Authorization', 'Bearer '
        post rpc_url, { jsonrpc: '2.0', method: 'health.check', id: 1, params: [] }.to_json
        expect(last_response.status).to eq(401)
      end

      it 'returns 401 for a whitespace Bearer token' do
        header 'Authorization', 'Bearer    '
        post rpc_url, { jsonrpc: '2.0', method: 'health.check', id: 1, params: [] }.to_json
        expect(last_response.status).to eq(401)
      end
    end

    # boot! normally guarantees one of these is configured, but the auth layer must
    # fail closed with a 401 rather than a 500 if it was bypassed.
    context 'when neither a token nor a database is configured' do
      before do
        app.settings.api_token = nil
        app.settings.db_manager = nil
      end

      it 'returns 401' do
        post rpc_url, { jsonrpc: '2.0', method: 'health.check', id: 1, params: [] }.to_json
        expect(last_response.status).to eq(401)
      end
    end

    # Validating a token against database users needs the local database - users(persistence_token:)
    # and create_new_user_token are not part of the remote data service API. That is the same
    # reason boot! refuses database backed authentication when a remote data service is
    # configured, so this path does not exist under REMOTE_DB rather than merely being awkward
    # to set up there.
    context 'when a DB user token is used', if: ENV['REMOTE_DB'].nil? do
      let(:user) do
        Mdm::User.where(username: 'test_user').first_or_create!(
          crypted_password: BCrypt::Password.create('test_password'),
          admin: false
        )
      end
      let(:user_token) { framework.db.create_new_user_token(id: user.id, token_length: 40) }

      before do
        # Mirrors the production wiring in boot!, which stores framework.db itself.
        app.settings.api_token = nil
        app.settings.db_manager = framework.db
      end

      it 'allows requests with the correct user token' do
        header 'Authorization', "Bearer #{user_token}"
        post rpc_url, { jsonrpc: '2.0', method: 'health.check', id: 1, params: [] }.to_json
        expect(last_response.status).not_to eq(401)
      end

      it 'rejects requests with an invalid token' do
        header 'Authorization', 'Bearer invalid_token'
        post rpc_url, { jsonrpc: '2.0', method: 'health.check', id: 1, params: [] }.to_json
        expect(last_response.status).to eq(401)
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
              vuln: {},
              message: 'The target is not exploitable.',
              reason: nil
            }
          }
        }
        expect(last_json_response).to include(expected_completed_response)
      end
    end

    context 'when the module does not support a check method' do
      let(:module_name) { 'scanner/http/title' }

      # rpc_check short-circuits with error(500, Msf::Exploit::CheckCode::Unsupported.message)
      # when the target module lacks a check method. That raises Msf::RPC::Exception,
      # which the JSON-RPC dispatcher wraps into a well-formed application-server-error
      # envelope and returns as HTTP 200 (per the JSON-RPC 2.0 convention that error
      # responses share the transport status of successful responses).
      it 'returns a JSON-RPC application-server-error envelope' do
        create_job
        expect(last_response).to be_ok

        expected_error_response = {
          jsonrpc: '2.0',
          error: {
            code: -32000,
            data: {
              code: 500
            },
            message: 'Application server error: This module does not support check.'
          },
          id: 1
        }
        expect(last_json_response).to include(expected_error_response)
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
          raise 'Unexpected module error'
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
            error: "Unexpected module error"
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
              host: {
                address: host_ip,
                modules: [
                  {
                    mname: "exploit/windows/smb/ms17_010_eternalblue",
                    mtype: "exploit",
                    options: {
                      invalid: [],
                      missing: [],
                    },
                    state: "READY_FOR_TEST",
                    description: "ready for testing"
                  },
                  {
                    mname: "exploit/windows/smb/ms17_010_psexec",
                    mtype: "exploit",
                    options: {
                      invalid: [],
                      missing: [ "credential" ],
                    },
                    state: "REQUIRES_CRED",
                    description: "credentials are required"
                  },
                  {
                    mname: "exploit/windows/smb/smb_doublepulsar_rce",
                    mtype: "exploit",
                    options: {
                      invalid: [],
                      missing: [],
                    },
                    state: "READY_FOR_TEST",
                    description: "ready for testing"
                  }
                ]
              }
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
              host: {
                address: host_ip,
                modules: [
                  {
                    mname: "exploit/windows/smb/ms17_010_eternalblue",
                    mtype: "exploit",
                    options: {
                      invalid: [],
                      missing: [ "payload_match" ],
                    },
                    state: "MISSING_PAYLOAD",
                    description: "none of the requested payloads match"
                  },
                  {
                    mname: "exploit/windows/smb/ms17_010_psexec",
                    mtype: "exploit",
                    options: {
                      invalid: [],
                      missing: [ "credential", "payload_match" ],
                    },
                    state: "REQUIRES_CRED",
                    description: "credentials are required, none of the requested payloads match"
                  },
                  {
                    mname: "exploit/windows/smb/smb_doublepulsar_rce",
                    mtype: "exploit",
                    options: {
                      invalid: [],
                      missing: ["payload_match"],
                    },
                    state: "MISSING_PAYLOAD",
                    description: "none of the requested payloads match"
                  }
                ]
              }
            },
            id: 1
          }

          analyze_host(
            {
              workspace: 'default',
              host: host_ip,
              analyze_options: {
                payloads: [
                  'linux/x86/meterpreter_reverse_http'
                ]
              }
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
            host: {
              address: host_ip,
              modules: []
            }
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
