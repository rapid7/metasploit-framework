# encoding: UTF-8

require 'rex/proto/sip/util'
include Rex::Proto::SIP

describe 'Rex::Proto::SIP SIP utility methods' do
  describe 'Extracts headers correctly' do
    headerless_response = 'Look, no headers'
    specify { extract_headers(headerless_response).should be_nil }
    response_with_headers = <<EOF
H1: v1
H2: v2
H3: v3
H2: v21
EOF
    expected_headers = { 'H1' => %w(v1), 'H2' => %w(v2 v21), 'H3' => %w(v3) }
    specify { extract_headers(response_with_headers).should == expected_headers }
  end
end
