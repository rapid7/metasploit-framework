# -*- coding:binary -*-

require 'spec_helper'

RSpec.describe Msf::OptRhosts do
  # Normalized values are just the original value for OptAddressRange
  valid_values = [
    { value: '192.0.2.0/24', normalized: '192.0.2.0/24' },
    { value: '192.0.2.0-255', normalized: '192.0.2.0-255' },
    { value: '192.0.2.0,1-255', normalized: '192.0.2.0,1-255' },
    { value: '192.0.2.*', normalized: '192.0.2.*' },
    { value: '192.0.2.0-192.0.2.255', normalized: '192.0.2.0-192.0.2.255' },
    {
      value: "file:#{File.expand_path('short_address_list.txt', FILE_FIXTURES_PATH)}",
      normalized: "file:#{File.expand_path('short_address_list.txt', FILE_FIXTURES_PATH)}"
    },
    {
      value: "file://#{File.expand_path('short_address_list.txt', FILE_FIXTURES_PATH)}",
      normalized: "file://#{File.expand_path('short_address_list.txt', FILE_FIXTURES_PATH)}"
    },
    {
      value: "127.0.0.1, cidr:/31:http://192.0.2.0/tomcat/manager, https://192.0.2.0:8080/manager/html file://#{File.expand_path('short_address_list.txt', FILE_FIXTURES_PATH)}",
      normalized: "127.0.0.1, cidr:/31:http://192.0.2.0/tomcat/manager, https://192.0.2.0:8080/manager/html file://#{File.expand_path('short_address_list.txt', FILE_FIXTURES_PATH)}"
    },
  ]
  invalid_values = [
    # Too many dots
    { value: '192.0.2.0.0' },
    { value: '192.0.2.0.0,1' },
    { value: '192.0.2.0.0,1-2' },
    { value: '192.0.2.0.0/24' },
    # Not enough dots
    { value: '192.0.2' },
    { value: '192.0.2,1' },
    { value: '192.0.2,1-2' },
    { value: '192.0.2/24' },
    # Can't mix ranges and CIDR
    { value: '192.0.2.0,1/24' },
    { value: '192.0.2.0-1/24' },
    { value: '192.0.2.0,1-2/24' },
    { value: '192.0.2.0/1-24' },
    { value: '192.0.2.0-192.0.2.1-255' },

    # Invalid urls
    { value: 'http:|' },
    { value: 'http://' },
    { value: 'cidr:http://' },

    # Non-string values
    { value: true },
    { value: 5 },
    { value: [] },
    { value: [1, 2] },
    { value: {} },
  ]

  it_behaves_like 'an option', valid_values, invalid_values, 'rhosts'
end
