require 'mkmf'
if /i386-mingw32/ =~ RUBY_PLATFORM
	dir_config("pcap","C:/WpdPack/include","C:/WpdPack/lib")
	have_library("wpcap", "pcap_open_live")
	have_library("wpcap", "pcap_setnonblock")
else
	have_library("pcap", "pcap_open_live")
	have_library("pcap", "pcap_setnonblock")
end

if ( RUBY_VERSION =~ /^1\.9/ )
	$CFLAGS += " -DRUBY_19"
end

create_makefile("pcaprub")
