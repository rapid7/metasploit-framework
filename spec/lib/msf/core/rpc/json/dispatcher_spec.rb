require 'spec_helper'
require 'json'

require 'msf/core/rpc'

RSpec.describe Msf::RPC::JSON::Dispatcher do
  include_context 'Msf::Simple::Framework'

  def to_json(data)
    return nil if data.nil?

    json = data.to_json
    return json.to_s
  end

  describe '#process' do

    before(:each) do
      # prepare a dispatcher for all of the tests
      @dispatcher = Msf::RPC::JSON::Dispatcher.new(framework)
    end

    context 'invalid JSON-RPC request' do

      before(:each) do
        # mock RpcCommand behavior as it isn't relevant for JSON-RPC validation
        cmd = instance_double('RpcCommand')
        allow(cmd).to receive(:execute).with(instance_of(String), instance_of(Array)).and_return({})
        allow(cmd).to receive(:execute).with(instance_of(String), instance_of(Hash)).and_return({})
        allow(cmd).to receive(:execute).with(instance_of(String), nil).and_return({})
        @dispatcher.set_command(cmd)
      end

      context 'is not valid JSON' do
        it 'contains only a string' do
          expected_response = {
              jsonrpc: '2.0',
              error: {
                  code: -32700,
                  message: 'Invalid JSON was received by the server. An error occurred on the server while parsing the JSON text.'
              },
              id: nil
          }
          expect(@dispatcher.process("Ce n'est pas un JSON")).to eq(expected_response.to_json)
        end
      end

      context 'is not a valid request object' do
        expected_response = {
            jsonrpc: '2.0',
            error: {
                code: -32600,
                message: 'The JSON sent is not a valid Request object.'
            },
            id: nil
        }

        it 'does not contain required jsonrpc member' do
          request = '{ "method": "unit-test" }'
          expect(@dispatcher.process(request)).to eq(expected_response.to_json)
        end

        it 'does not contain required method member' do
          request = '{ "jsonrpc": "2.0" }'
          expect(@dispatcher.process(request)).to eq(expected_response.to_json)
        end

        it 'does not contain valid JSON-RPC version number' do
          request = '{ "jsonrpc": "1.0", "method": "unit-test" }'
          expect(@dispatcher.process(request)).to eq(expected_response.to_json)
        end

        it 'is an empty JSON object' do
          expect(@dispatcher.process('{}')).to eq(expected_response.to_json)
        end

        it 'is an array with an empty JSON object' do
          expect(@dispatcher.process('[{}]')).to eq([expected_response].to_json)
        end

        it 'is an array with an empty array' do
          expect(@dispatcher.process('[[]]')).to eq([expected_response].to_json)
        end

        it 'is an array with a string' do
          expect(@dispatcher.process('["bad"]')).to eq([expected_response].to_json)
        end

        it 'is an array with a number' do
          expect(@dispatcher.process('[123456]')).to eq([expected_response].to_json)
        end

        it 'is an array with true' do
          expect(@dispatcher.process('[true]')).to eq([expected_response].to_json)
        end

        it 'is an array with false' do
          expect(@dispatcher.process('[false]')).to eq([expected_response].to_json)
        end

        it 'is an array with null' do
          expect(@dispatcher.process('[null]')).to eq([expected_response].to_json)
        end

        context 'contains incorrect data type' do
          context 'jsonrpc' do
            it 'is a number' do
              request = '{ "jsonrpc": 2.0, "method": "unit-test" }'
              expect(@dispatcher.process(request)).to eq(expected_response.to_json)
            end

            it 'is an empty JSON object' do
              request = '{ "jsonrpc": {}, "method": "unit-test" }'
              expect(@dispatcher.process(request)).to eq(expected_response.to_json)
            end

            it 'is an empty array' do
              request = '{ "jsonrpc": [], "method": "unit-test" }'
              expect(@dispatcher.process(request)).to eq(expected_response.to_json)
            end

            it 'is null' do
              request = '{ "jsonrpc": null, "method": "unit-test" }'
              expect(@dispatcher.process(request)).to eq(expected_response.to_json)
            end
          end

          context 'method' do
            it 'is a number' do
              request = '{ "jsonrpc": "2.0", "method": 123456 }'
              expect(@dispatcher.process(request)).to eq(expected_response.to_json)
            end

            it 'is an empty JSON object' do
              request = '{ "jsonrpc": "2.0", "method": {} }'
              expect(@dispatcher.process(request)).to eq(expected_response.to_json)
            end

            it 'is an empty array' do
              request = '{ "jsonrpc": "2.0", "method": [] }'
              expect(@dispatcher.process(request)).to eq(expected_response.to_json)
            end

            it 'is null' do
              request = '{ "jsonrpc": "2.0", "method": null }'
              expect(@dispatcher.process(request)).to eq(expected_response.to_json)
            end
          end

          context 'params' do
            it 'is a number' do
              request = '{ "jsonrpc": "2.0", "method": "unit-test", "params": 123456 }'
              expect(@dispatcher.process(request)).to eq(expected_response.to_json)
            end

            it 'is a string' do
              request = '{ "jsonrpc": "2.0", "method": "unit-test", "params": "bad-params" }'
              expect(@dispatcher.process(request)).to eq(expected_response.to_json)
            end

            it 'is true' do
              request = '{ "jsonrpc": "2.0", "method": "unit-test", "params": true }'
              expect(@dispatcher.process(request)).to eq(expected_response.to_json)
            end

            it 'is false' do
              request = '{ "jsonrpc": "2.0", "method": "unit-test", "params": false }'
              expect(@dispatcher.process(request)).to eq(expected_response.to_json)
            end

            it 'is null' do
              request = '{ "jsonrpc": "2.0", "method": "unit-test", "params": null }'
              expect(@dispatcher.process(request)).to eq(expected_response.to_json)
            end
          end

          context 'id' do
            it 'is an empty JSON object' do
              request = '{ "jsonrpc": "2.0", "method": "unit-test", "id": {} }'
              expect(@dispatcher.process(request)).to eq(expected_response.to_json)
            end

            it 'is an empty array' do
              request = '{ "jsonrpc": "2.0", "method": "unit-test", "id": [] }'
              expect(@dispatcher.process(request)).to eq(expected_response.to_json)
            end

            it 'is an array that contains a number' do
              request = '{ "jsonrpc": "2.0", "method": "unit-test", "id": [1] }'
              expect(@dispatcher.process(request)).to eq(expected_response.to_json)
            end

            it 'is a number that contain fractional parts' do
              request = '{ "jsonrpc": "2.0", "method": "unit-test", "id": 3.14 }'
              expect(@dispatcher.process(request)).to eq(expected_response.to_json)
            end

            it 'is true' do
              request = '{ "jsonrpc": "2.0", "method": "unit-test", "id": true }'
              expect(@dispatcher.process(request)).to eq(expected_response.to_json)
            end

            it 'is false' do
              request = '{ "jsonrpc": "2.0", "method": "unit-test", "id": false }'
              expect(@dispatcher.process(request)).to eq(expected_response.to_json)
            end
          end
        end
      end
    end

    context 'errors on JSON-RPC method execute' do
      it 'does not contain valid method name' do
        # mock RpcCommand behavior for MethodNotFound exception
        method_name = 'DNE'
        cmd = instance_double('RpcCommand')
        allow(cmd).to receive(:execute).with(instance_of(String), instance_of(Array)).and_raise(Msf::RPC::JSON::MethodNotFound.new(method_name))
        allow(cmd).to receive(:execute).with(instance_of(String), instance_of(Hash)).and_raise(Msf::RPC::JSON::MethodNotFound.new(method_name))
        allow(cmd).to receive(:execute).with(instance_of(String), nil).and_raise(Msf::RPC::JSON::MethodNotFound.new(method_name))
        @dispatcher.set_command(cmd)

        expected_response = {
            jsonrpc: '2.0',
            error: {
                code: -32601,
                message: 'The method %<name>s does not exist.' % { name: method_name }
            },
            id: 1
        }
        request = '{ "jsonrpc": "2.0", "method": "DNE", "params": [], "id": 1 }'
        expect(@dispatcher.process(request)).to eq(expected_response.to_json)
      end

      it 'does not contain valid method params' do
        # mock RpcCommand behavior for InvalidParams exception
        cmd = instance_double('RpcCommand')
        allow(cmd).to receive(:execute).with(instance_of(String), instance_of(Array)).and_raise(ArgumentError)
        allow(cmd).to receive(:execute).with(instance_of(String), instance_of(Hash)).and_raise(ArgumentError)
        allow(cmd).to receive(:execute).with(instance_of(String), nil).and_raise(ArgumentError)
        @dispatcher.set_command(cmd)

        expected_response = {
            jsonrpc: '2.0',
            error: {
                code: -32602,
                message: 'Invalid method parameter(s).'
            },
            id: 1
        }
        request = '{ "jsonrpc": "2.0", "method": "unit-test", "params": ["method-has-no-params"], "id": 1 }'
        expect(@dispatcher.process(request)).to eq(expected_response.to_json)
      end

      it 'throws Msf::RPC::Exception' do
        # mock RpcCommand behavior for Msf::RPC::Exception exception
        error_code = 123
        error_msg = 'unit-test'
        cmd = instance_double('RpcCommand')
        allow(cmd).to receive(:execute).with(instance_of(String), nil).and_raise(Msf::RPC::Exception.new(error_code, error_msg))
        allow(cmd).to receive(:execute).with(instance_of(String), nil).and_raise(Msf::RPC::Exception.new(error_code, error_msg))
        allow(cmd).to receive(:execute).with(instance_of(String), nil).and_raise(Msf::RPC::Exception.new(error_code, error_msg))
        @dispatcher.set_command(cmd)

        expected_response = {
            jsonrpc: '2.0',
            error: {
                code: -32000,
                message: 'Application server error: %<msg>s' % { msg: error_msg },
                data: {
                    code: error_code
                }
            },
            id: 1
        }
        request = '{ "jsonrpc": "2.0", "method": "unit-test", "id": 1 }'
        expect(@dispatcher.process(request)).to eq(expected_response.to_json)
      end

      it 'throws StandardError' do
        # mock RpcCommand behavior for StandardError exception
        error_msg = 'unit-test'
        cmd = instance_double('RpcCommand')
        allow(cmd).to receive(:execute).with(instance_of(String), nil).and_raise(StandardError.new(error_msg))
        allow(cmd).to receive(:execute).with(instance_of(String), nil).and_raise(StandardError.new(error_msg))
        allow(cmd).to receive(:execute).with(instance_of(String), nil).and_raise(StandardError.new(error_msg))
        @dispatcher.set_command(cmd)

        expected_response = {
            jsonrpc: '2.0',
            error: {
                code: -32000,
                message: 'Application server error: %<msg>s' % { msg: error_msg }
            },
            id: 1
        }
        request = '{ "jsonrpc": "2.0", "method": "unit-test", "id": 1 }'
        expect(@dispatcher.process(request)).to eq(expected_response.to_json)
      end
    end
  end
end
