require 'msf/core/handler/bind_tcp'
require 'msf/core/handler/find_port'
require 'msf/core/handler/find_shell'
require 'msf/core/handler/find_tag'
require 'msf/core/handler/find_tty'
require 'msf/core/handler/none'
require 'msf/core/handler/reverse_http'
require 'msf/core/handler/reverse_https'
require 'msf/core/handler/reverse_https_proxy'
require 'msf/core/handler/reverse_ipv6_http'
require 'msf/core/handler/reverse_ipv6_https'
require 'msf/core/handler/reverse_tcp'
require 'msf/core/handler/reverse_tcp_all_ports'
require 'msf/core/handler/reverse_tcp_double'
require 'msf/core/handler/reverse_tcp_double_ssl'
require 'msf/core/handler/reverse_tcp_ssl'

msf_handlers =  [
    Msf::Handler::BindTcp,
    Msf::Handler::FindPort,
    Msf::Handler::FindShell,
    Msf::Handler::FindTag,
    Msf::Handler::FindTty,
    Msf::Handler::None,
    Msf::Handler::ReverseHttp,
    Msf::Handler::ReverseHttps,
    Msf::Handler::ReverseHttpsProxy,
    Msf::Handler::ReverseIPv6Http,
    Msf::Handler::ReverseIPv6Https,
    Msf::Handler::ReverseTcp,
    Msf::Handler::ReverseTcpAllPorts,
    Msf::Handler::ReverseTcpDouble,
    Msf::Handler::ReverseTcpDoubleSSL,
    Msf::Handler::ReverseTcpSsl
]
msf_handler_count = msf_handlers.length

FactoryGirl.define do
  sequence :msf_handler do |n|
    msf_handlers[n % msf_handler_count]
  end
end
