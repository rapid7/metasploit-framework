# -*- coding: binary -*-
require 'msf/core/modules/external'
require 'base64'
require 'json'

class Msf::Modules::External::Message

  attr_reader :method, :id
  attr_accessor :params

  def initialize(m)
    self.method = m
    self.params = {}
    self.id = Base64.strict_encode64(SecureRandom.random_bytes(16))
  end

  def to_json
    JSON.generate({jsonrpc: '2.0', id: self.id, method: self.method, params: self.params.to_h})
  end

  protected

  attr_writer :method, :id
end
