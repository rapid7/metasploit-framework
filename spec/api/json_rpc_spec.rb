require 'spec_helper'
require 'rack/test'
require 'msf/core/modules/loader/base'
require 'msf/core/web_services/json_rpc_app'

# These tests ensure the full end to end functionality of metasploit's JSON RPC
# endpoint. There are multiple layers of possible failure in our API, and unit testing
# alone will not cover all edge cases. For instance, middleware may raise exceptions
# and return HTML to the calling client unintentionally - which will break our JSON
# response contract. These test should help catch such scenarios.
RSpec.describe ::Msf::WebServices::JsonRpcApp do
  include Rack::Test::Methods
  include_context 'Metasploit::Framework::Spec::Constants cleaner'

  let(:app) { subject }
  let(:api_url) { '/api/v1/json-rpc' }
  let(:framework) { app.settings.framework }
  let(:module_name) { 'scanner/ssl/openssl_heartbleed' }
  let(:a_valid_result_uuid) { { 'result' => hash_including({ 'uuid' => match(/\w+/) }) } }

  def create_job
    post api_url, {
      'jsonrpc': '2.0',
      'method': 'module.check',
      'id': 1,
      'params': [
        'auxiliary',
        module_name,
        {
          'RHOSTS': '192.168.0.0'
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

    context 'when the module has an internal error' do
      before(:each) do
        allow_any_instance_of(::Msf::Auxiliary::Scanner).to receive(:check).and_raise(Timeout::Error)
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
            'error' => 'Timeout::Error'
          }
        }
        expect(last_json_response).to include(expected_error_response)
      end
    end
  end
end
