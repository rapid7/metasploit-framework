require 'mkmf'

have_library("pcap", "pcap_open_live")
create_makefile("pcaprub")
