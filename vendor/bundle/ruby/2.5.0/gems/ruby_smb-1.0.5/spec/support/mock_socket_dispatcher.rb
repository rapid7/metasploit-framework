require 'ruby_smb/dispatcher'
class MockSocketDispatcher < RubySMB::Dispatcher::Base
  def recv_packet
    ''
  end

  def send_packet(packet); end
end
