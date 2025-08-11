# -*- coding:binary -*-

require 'spec_helper'

RSpec.describe Msf::OptKerberosCredentialCache do
  it_behaves_like 'a database ref or path option', expected_type: 'kerberos_credential_cache'
end
