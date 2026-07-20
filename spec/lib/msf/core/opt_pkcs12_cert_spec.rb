# -*- coding:binary -*-

require 'spec_helper'

RSpec.describe Msf::OptPkcs12Cert do
  it_behaves_like 'a database ref or path option', expected_type: 'pkcs12_cert'
end
