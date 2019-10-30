# -*- coding:binary -*-
require 'spec_helper'
require 'msf/base/sessions/mainframe_shell'

##
#
#  A quick test that MainframeShell is operable
#  Author: Bigendian Smalls
#
RSpec.describe Msf::Sessions::MainframeShell do
  it 'extends Msf::Sessions::CommandShell to include EBCDIC cp1047 codepage translation' do
  args=[0,
   {:datastore=>
     {"VERBOSE"=>false,
      "WfsDelay"=>0,
      "EnableContextEncoding"=>false,
      "DisablePayloadHandler"=>false,
      "ConnectTimeout"=>10,
      "TCP::max_send_size"=>0,
      "TCP::send_delay"=>0,
      "RPORT"=>4444,
      "payload"=>"mainframe/shell_reverse_notranslate_tcp",
      "LPORT"=>5555,
      "LHOST"=>"127.0.0.1",
      "RHOST"=>"127.0.0.2",
      "CPORT"=>0,
      "ReverseConnectRetries"=>5,
      "ReverseAllowProxy"=>false,
      "ReverseListenerThreaded"=>false,
      "InitialAutoRunScript"=>"",
      "AutoRunScript"=>"",
      "ReverseListenerBindPort"=>0,
      "TARGET"=>0},
    :expiration=>0,
    :comm_timeout=>0,
    :retry_total=>0,
    :retry_wait=>0}]
    expect(described_class.name).to eq('Msf::Sessions::MainframeShell')
    mfshell = Msf::Sessions::MainframeShell.new(args)
    expect(mfshell.platform).to eq('mainframe')
    expect(mfshell.arch).to eq('zarch')
    expect(mfshell.respond_to?(:translate_1047))
  end
end
