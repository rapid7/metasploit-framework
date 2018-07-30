# -*- coding: binary -*-
require 'msf/core/modules/external'
require 'base64'
require 'json'
require 'securerandom'

class Msf::Modules::External::Message

  attr_reader :method
  attr_accessor :params, :id

  def self.from_module(j)
    if j['method']
      m = self.new(j['method'].to_sym)
      m.params = j['params']
      m
    elsif j['result']
      m = self.new(:reply)
      m.params = j['result']
      m.id = j['id']
      m
    end
  end

  def initialize(m)
    self.method = m
    self.params = {}
    self.id = Base64.strict_encode64(SecureRandom.random_bytes(16))
  end

  def to_json
    params =
      if self.params.respond_to? :to_nested_values
        self.params.to_nested_values
      else
        self.params.to_h
      end
    JSON.generate({jsonrpc: '2.0', id: self.id, method: self.method, params: params})
  end

  protected

  attr_writer :method
end
