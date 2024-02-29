# -*- coding: binary -*-

require 'spec_helper'
require 'rex/proto/mysql/client'

RSpec.describe Rex::Proto::MySQL::Client do
  it { is_expected.to be_a ::Mysql }

  [
    { method: :peerhost, return_type: String },
    { method: :peerport, return_type: Integer },
    { method: :current_database, return_type: String }
  ].each do |method_hash|
    it { is_expected.to respond_to method_hash[:method] }
  end
end
