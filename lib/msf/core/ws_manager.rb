# -*- coding: binary -*-
require 'msf/core/rpc/ws/ws_event_notify'

module Msf
  # Ws
  class WebSocketManager
    include Framework::Offspring

    attr_accessor :handlers
    def initialize(framework)
      self.framework = framework
      self.clients = { notify: [] }
      self.handlers = {}

      add_handler(:notify, Msf::WS::EventNotify.new(framework, {}))
    end

    def register(type, ws)
      clients[type] = [] if !clients.key?(type)
      clients[type] << ws if !clients[type].include?(ws)
    end

    def deregister(type, ws)
      clients[type] = [] if !clients.key?(type)
      clients[type].delete(ws) if clients[type].include?(ws)
    end

    def wrap_websocket_data(type, action, data)
      res = { type: type, action: action, data: data }
      res.to_json
    end

    def notify(type, message)
      clients[type].each { |client| client.send(message) }
    end

    def add_handler(group, handler)
      handlers[group] = handler
    end

    attr_accessor :websocket # :nodoc:
    attr_accessor :clients # :nodoc:

  end
end
