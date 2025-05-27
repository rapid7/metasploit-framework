# -*- coding:binary -*-

require 'spec_helper'

RSpec.describe Msf::OptProxies do

  valid_values = [
    nil,
    '',
    '            ',
    'socks5:198.51.100.1:1080',
    'socks4:198.51.100.1:1080',
    'http:198.51.100.1:8080,socks4:198.51.100.1:1080',
    'http:198.51.100.1:8080,       socks4:198.51.100.1:1080',
    'sapni:198.51.100.1:8080,       socks4:198.51.100.1:1080',
  ].map { |value| { value: value, normalized: value } }

  invalid_values = [
    { :value => 123 },
    { :value => 'foo(' },
    { :value => 'foo:198.51.100.1:8080' },
    { :value => 'foo:198.51.100.18080' },
    { :value => 'foo::' },
  ]

  it_behaves_like "an option", valid_values, invalid_values, 'proxies'
end
