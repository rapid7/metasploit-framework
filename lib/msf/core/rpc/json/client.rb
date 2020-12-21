require 'json'
require 'uri'

require 'msf/core/rpc'

module Msf::RPC::JSON
  # JSON-RPC Client
  # All client method call requests must be dispatched from within an
  # EventMachine (reactor) run loop.
  class Client
    attr_reader :uri
    attr_reader :api_token
    attr_reader :symbolize_names
    attr_accessor :namespace

    # Instantiate a Client.
    # @param uri [String] the JSON-RPC service URI
    # @param api_token [String] the API token. Default: nil
    # @param namespace [String] the namespace for the JSON-RPC method. The namespace will
    # be prepended to the method name with a period separator. Default: nil
    # @param symbolize_names [Boolean] If true, symbols are used for the names (keys) when
    # processing JSON objects; otherwise, strings are used. Default: true
    # @param private_key_file [String] the SSL private key file used for the HTTPS request. Default: nil
    # @param cert_chain_file [String] the SSL cert chain file used for the HTTPS request. Default: nil
    # @param verify_peer [Boolean] indicates whether a server should request a certificate
    # from a peer, to be verified by user code. Default: nil
    def initialize(uri, api_token: nil, namespace: nil, symbolize_names: true,
                   private_key_file: nil, cert_chain_file: nil, verify_peer: nil)
      @uri = URI.parse(uri)
      @api_token = api_token
      @namespace = namespace
      @symbolize_names = symbolize_names
      @private_key_file = private_key_file
      @cert_chain_file = cert_chain_file
      @verify_peer = verify_peer
    end

    private

    # Invoked by Ruby when obj is sent a message it cannot handle, then processes
    # the call as an RPC method invocation.
    # @param symbol [Symbol] the symbol for the method called
    # @param args [Array] any positional arguments passed to the method
    # @param keyword_args [Hash] any keyword arguments passed to the method
    # @returns [Msf::RPC::JSON::Request] an EM::Deferrable for the RPC method invocation.
    def method_missing(symbol, *args, **keyword_args, &block)
      # assemble method parameters
      if !args.empty? && !keyword_args.empty?
        params = args << keyword_args
      elsif !args.empty?
        params = args
      elsif !keyword_args.empty?
        params = keyword_args
      else
        params = nil
      end

      process_call_async(symbol, params)
    end

    # Asynchronously processes the RPC method invocation.
    # @param method [Symbol] the method
    # @param params [Array, Hash] any arguments passed to the method
    # @returns [Msf::RPC::JSON::Request] an EM::Deferrable for the RPC method invocation.
    def process_call_async(method, params)
      req = Request.new(@uri,
                        api_token: @api_token,
                        method: method,
                        params: params,
                        namespace: @namespace,
                        symbolize_names: @symbolize_names,
                        private_key_file: @private_key_file,
                        cert_chain_file: @cert_chain_file,
                        verify_peer: @verify_peer)
      req.send

      req
    end
  end
end