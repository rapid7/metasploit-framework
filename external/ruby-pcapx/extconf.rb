require 'mkmf'

pcap_dir        = with_config("pcap-dir", "/usr/local")
pcap_includedir = with_config("pcap-includedir", pcap_dir + "/include")
pcap_libdir     = with_config("pcap-libdir", pcap_dir + "/lib")

$CFLAGS  = "-I#{pcap_includedir}"
$LDFLAGS = "-L#{pcap_libdir}"

have_library("socket", "socket")
have_library("xnet", "gethostbyname")
have_func("hstrerror")
if have_header("pcap.h") && have_library("pcap", "pcap_open_live")
  have_func("pcap_compile_nopcap")
  create_makefile("pcap")
end
