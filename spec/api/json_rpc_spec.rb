require 'spec_helper'
require 'msf/core/rpc'
require 'rack/test'
require 'rack/protection'

# These tests ensure the full end to end functionality of metasploit's JSON RPC
# endpoint. There are multiple layers of possible failure in our API, and unit testing
# alone will not cover all edge cases. For instance, middleware may raise exceptions
# and return HTML to the calling client unintentionally - which will break our JSON
# response contract. These test should help catch such scenarios.
RSpec.describe "Metasploit's json-rpc" do
  include Rack::Test::Methods
  include_context 'Metasploit::Framework::Spec::Constants cleaner'
  include_context 'Msf::Framework#threads cleaner'

  let(:app) { subject }
  let(:api_url) { '/api/v1/json-rpc' }
  let(:framework) { app.settings.framework }
  let(:module_name) { 'scanner/ssl/openssl_heartbleed' }
  let(:a_valid_result_uuid) { { 'result' => hash_including({ 'uuid' => match(/\w+/) }) } }
  let(:app) do
    # Lazy load to ensure that the json rpc app doesn't create an instance of framework out of band
    require 'msf/core/web_services/json_rpc_app'
    ::Msf::WebServices::JsonRpcApp.new
  end

  before(:example) do
    allow(framework.db).to receive(:active).and_return(false)
  end

  def create_job
    post api_url, {
      'jsonrpc': '2.0',
      'method': 'module.check',
      'id': 1,
      'params': [
        'auxiliary',
        module_name,
        {
          'RHOSTS': '192.0.2.0'
        }
      ]
    }.to_json
  end

  def get_job_results(uuid)
    post api_url, {
      'jsonrpc': '2.0',
      'method': 'module.results',
      'id': 1,
      'params': [
        uuid
      ]
    }.to_json
  end

  def last_json_response
    JSON.parse(last_response.body)
  end

  def expect_completed_status(rpc_response)
    expect(rpc_response).to include({ 'result' => hash_including({ 'status' => 'completed' }) })
  end

  def expect_error_status(rpc_response)
    expect(rpc_response).to include({ 'result' => hash_including({ 'status' => 'errored' }) })
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
          'result' => {
            'status' => 'completed',
            'result' => {
              'code' => 'safe',
              'message' => 'The target is not exploitable.',
              'reason' => nil
            }
          }
        }
        expect(last_json_response).to include(expected_completed_response)
      end
    end

    context 'when the check command raises a known msf error' do
      before(:each) do
        allow_any_instance_of(::Msf::Auxiliary::Scanner).to receive(:check) do |mod|
          mod.fail_with(Msf::Module::Failure::UnexpectedReply, "Expected failure reason")
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
          'result' => {
            'status' => 'errored',
            'error' => 'unexpected-reply: Expected failure reason'
          }
        }
        expect(last_json_response).to include(expected_error_response)
      end
    end

    context 'when the check command has an unexpected error' do
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
          'result' => {
            'status' => 'errored',
            'error' => "undefined method `body' for nil:NilClass"
          }
        }
        expect(last_json_response).to include(expected_error_response)
      end
    end

    context "when there is a sinatra level application error in the development environment" do
      before(:each) do
        allow_any_instance_of(Msf::RPC::JSON::Dispatcher).to receive(:process) do
          raise Exception, "Sinatra level exception raised"
        end
        mock_rack_env("development")
      end

      it 'returns the error results' do
        create_job

        expect(last_response).to be_server_error
        expected_error_response = {
          "error" => {
            "code" => -32000,
            "data" => {
              "backtrace" => include(a_kind_of(String))
            },
            "message" => "Application server error: Sinatra level exception raised"
          },
          "id" => 1
        }
        expect(last_json_response).to include(expected_error_response)
      end
    end

    context "when rack middleware raises an error in the development environment" do
      before(:each) do
        allow_any_instance_of(::Rack::Protection::AuthenticityToken).to receive(:accepts?) do
          raise Exception, "Middleware error raised"
        end

        mock_rack_env("development")
      end

      it 'returns the error results' do
        create_job

        expect(last_response).to be_server_error
        expected_error_response = {
          "error" => {
            "code" => -32000,
            "data" => {
              "backtrace" => include(a_kind_of(String))
            },
            "message" => "Application server error: Middleware error raised"
          },
          "id" => 1
        }
        expect(last_json_response).to include(expected_error_response)
      end
    end

    context "when rack middleware raises an error in the production environment" do
      before(:each) do
        allow_any_instance_of(::Rack::Protection::AuthenticityToken).to receive(:accepts?) do
          raise Exception, "Middleware error raised"
        end
        mock_rack_env("production")
      end

      it 'returns the error results' do
        create_job

        expect(last_response).to be_server_error
        expected_error_response = {
          "error" => {
            "code" => -32000,
            "message" => "Application server error: Middleware error raised"
          },
          "id" => 1
        }
        expect(last_json_response).to include(expected_error_response)
      end
    end

    context "when there is a sinatra level application error in the production environment" do
      before(:each) do
        allow_any_instance_of(Msf::RPC::JSON::Dispatcher).to receive(:process) do
          raise Exception, "Sinatra level exception raised"
        end
        mock_rack_env("production")
      end

      it 'returns the error results' do
        create_job

        expect(last_response).to be_server_error
        expected_error_response = {
          "error" => {
            "code" => -32000,
            "message" => "Application server error: Sinatra level exception raised"
          },
          "id" => 1
        }
        expect(last_json_response).to include(expected_error_response)
      end
    end
  end
end
