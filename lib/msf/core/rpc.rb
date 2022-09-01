# -*- coding: binary -*-
require 'msf/core/rpc/v10/constants'

module Msf::RPC

  module JSON
    autoload :Client, 'msf/core/rpc/json/client'
    autoload :Dispatcher, 'msf/core/rpc/json/dispatcher'
    autoload :DispatcherHelper, 'msf/core/rpc/json/dispatcher_helper'
    autoload :Request, 'msf/core/rpc/json/request'
    autoload :Response, 'msf/core/rpc/json/response'
    autoload :RpcCommand, 'msf/core/rpc/json/rpc_command'
    autoload :RpcCommandFactory, 'msf/core/rpc/json/rpc_command_factory'

    # exception classes
    # server
    autoload :Error, 'msf/core/rpc/json/error'
    autoload :ParseError, 'msf/core/rpc/json/error'
    autoload :InvalidRequest, 'msf/core/rpc/json/error'
    autoload :MethodNotFound, 'msf/core/rpc/json/error'
    autoload :InvalidParams, 'msf/core/rpc/json/error'
    autoload :InternalError, 'msf/core/rpc/json/error'
    autoload :ServerError, 'msf/core/rpc/json/error'
    autoload :ApplicationServerError, 'msf/core/rpc/json/error'
    # client
    autoload :ClientError, 'msf/core/rpc/json/error'
    autoload :InvalidResponse, 'msf/core/rpc/json/error'
    autoload :JSONParseError, 'msf/core/rpc/json/error'
    autoload :ErrorResponse, 'msf/core/rpc/json/error'
  end
end
