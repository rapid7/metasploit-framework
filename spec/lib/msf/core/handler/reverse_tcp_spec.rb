require 'spec_helper'

RSpec.describe Msf::Handler::ReverseTcp do
  let(:socket_factory) { Rex::Socket::TcpServer }

  it_behaves_like 'a reverse handler listener'
end
