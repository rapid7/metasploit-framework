require 'spec_helper'

RSpec.describe 'modules/payloads', :content do
  modules_pathname = Pathname.new(__FILE__).parent.parent.parent.join('modules')

  include_context 'untested payloads', modules_pathname: modules_pathname

  context 'aix/ppc/shell_bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/aix/ppc/shell_bind_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'aix/ppc/shell_bind_tcp'
  end

  context 'aix/ppc/shell_find_port' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/aix/ppc/shell_find_port'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'aix/ppc/shell_find_port'
  end

  context 'aix/ppc/shell_interact' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/aix/ppc/shell_interact'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'aix/ppc/shell_interact'
  end

  context 'aix/ppc/shell_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/aix/ppc/shell_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'aix/ppc/shell_reverse_tcp'
  end

  context 'apple_ios/aarch64/meterpreter_reverse_http' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/apple_ios/aarch64/meterpreter_reverse_http'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'apple_ios/aarch64/meterpreter_reverse_http'
  end

  context 'apple_ios/aarch64/meterpreter_reverse_https' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/apple_ios/aarch64/meterpreter_reverse_https'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'apple_ios/aarch64/meterpreter_reverse_https'
  end

  context 'apple_ios/aarch64/meterpreter_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/apple_ios/aarch64/meterpreter_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'apple_ios/aarch64/meterpreter_reverse_tcp'
  end

  context 'apple_ios/aarch64/shell_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/apple_ios/aarch64/shell_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'apple_ios/aarch64/shell_reverse_tcp'
  end

  context 'apple_ios/armle/meterpreter_reverse_http' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/apple_ios/armle/meterpreter_reverse_http'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'apple_ios/armle/meterpreter_reverse_http'
  end

  context 'apple_ios/armle/meterpreter_reverse_https' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/apple_ios/armle/meterpreter_reverse_https'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'apple_ios/armle/meterpreter_reverse_https'
  end

  context 'apple_ios/armle/meterpreter_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/apple_ios/armle/meterpreter_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'apple_ios/armle/meterpreter_reverse_tcp'
  end

  context 'android/meterpreter_reverse_https' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/android/meterpreter_reverse_https'
                          ],
                          dynamic_size: true,
                          modules_pathname: modules_pathname,
                          reference_name: 'android/meterpreter_reverse_https'
  end

  context 'android/meterpreter_reverse_http' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/android/meterpreter_reverse_http'
                          ],
                          dynamic_size: true,
                          modules_pathname: modules_pathname,
                          reference_name: 'android/meterpreter_reverse_http'
  end

  context 'android/meterpreter_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/android/meterpreter_reverse_tcp'
                          ],
                          dynamic_size: true,
                          modules_pathname: modules_pathname,
                          reference_name: 'android/meterpreter_reverse_tcp'
  end

  context 'android/meterpreter/reverse_http' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/android/reverse_http',
                              'stages/android/meterpreter'
                          ],
                          dynamic_size: true,
                          modules_pathname: modules_pathname,
                          reference_name: 'android/meterpreter/reverse_http'
  end

  context 'android/meterpreter/reverse_https' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/android/reverse_https',
                              'stages/android/meterpreter'
                          ],
                          dynamic_size: true,
                          modules_pathname: modules_pathname,
                          reference_name: 'android/meterpreter/reverse_https'
  end

  context 'android/meterpreter/reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/android/reverse_tcp',
                              'stages/android/meterpreter'
                          ],
                          dynamic_size: true,
                          modules_pathname: modules_pathname,
                          reference_name: 'android/meterpreter/reverse_tcp'
  end

  context 'android/shell/reverse_http' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/android/reverse_http',
                              'stages/android/shell'
                          ],
                          dynamic_size: true,
                          modules_pathname: modules_pathname,
                          reference_name: 'android/shell/reverse_http'
  end

  context 'android/shell/reverse_https' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/android/reverse_https',
                              'stages/android/shell'
                          ],
                          dynamic_size: true,
                          modules_pathname: modules_pathname,
                          reference_name: 'android/shell/reverse_https'
  end

  context 'android/shell/reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/android/reverse_tcp',
                              'stages/android/shell'
                          ],
                          dynamic_size: true,
                          modules_pathname: modules_pathname,
                          reference_name: 'android/shell/reverse_tcp'
  end

  context 'bsd/sparc/shell_bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/bsd/sparc/shell_bind_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/sparc/shell_bind_tcp'
  end

  context 'bsd/sparc/shell_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/bsd/sparc/shell_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/sparc/shell_reverse_tcp'
  end

  context 'bsd/vax/shell_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/bsd/vax/shell_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/vax/shell_reverse_tcp'
  end

  context 'bsd/x64/exec' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/bsd/x64/exec'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/x64/exec'
  end

  context 'bsd/x64/shell_bind_ipv6_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/bsd/x64/shell_bind_ipv6_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/x64/shell_bind_ipv6_tcp'
  end

  context 'bsd/x64/shell_bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/bsd/x64/shell_bind_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/x64/shell_bind_tcp'
  end

  context 'bsd/x64/shell_bind_tcp_small' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/bsd/x64/shell_bind_tcp_small'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/x64/shell_bind_tcp_small'
  end

  context 'bsd/x64/shell_reverse_ipv6_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/bsd/x64/shell_reverse_ipv6_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/x64/shell_reverse_ipv6_tcp'
  end

  context 'bsd/x64/shell_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/bsd/x64/shell_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/x64/shell_reverse_tcp'
  end

  context 'bsd/x64/shell_reverse_tcp_small' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/bsd/x64/shell_reverse_tcp_small'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/x64/shell_reverse_tcp_small'
  end

  context 'bsd/x86/exec' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/bsd/x86/exec'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/x86/exec'
  end

  context 'bsd/x86/metsvc_bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/bsd/x86/metsvc_bind_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/x86/metsvc_bind_tcp'
  end

  context 'bsd/x86/metsvc_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/bsd/x86/metsvc_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/x86/metsvc_reverse_tcp'
  end

  context 'bsd/x86/shell/bind_ipv6_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/bsd/x86/bind_ipv6_tcp',
                              'stages/bsd/x86/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/x86/shell/bind_ipv6_tcp'
  end

  context 'bsd/x86/shell/bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/bsd/x86/bind_tcp',
                              'stages/bsd/x86/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/x86/shell/bind_tcp'
  end

  context 'bsd/x86/shell/find_tag' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/bsd/x86/find_tag',
                              'stages/bsd/x86/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/x86/shell/find_tag'
  end

  context 'bsd/x86/shell/reverse_ipv6_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/bsd/x86/reverse_ipv6_tcp',
                              'stages/bsd/x86/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/x86/shell/reverse_ipv6_tcp'
  end

  context 'bsd/x86/shell/reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/bsd/x86/reverse_tcp',
                              'stages/bsd/x86/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/x86/shell/reverse_tcp'
  end

  context 'bsd/x86/shell_bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/bsd/x86/shell_bind_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/x86/shell_bind_tcp'
  end

  context 'bsd/x86/shell_bind_tcp_ipv6' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/bsd/x86/shell_bind_tcp_ipv6'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/x86/shell_bind_tcp_ipv6'
  end

  context 'bsd/x86/shell_find_port' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/bsd/x86/shell_find_port'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/x86/shell_find_port'
  end

  context 'bsd/x86/shell_find_tag' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/bsd/x86/shell_find_tag'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/x86/shell_find_tag'
  end

  context 'bsd/x86/shell_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/bsd/x86/shell_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/x86/shell_reverse_tcp'
  end

  context 'bsd/x86/shell_reverse_tcp_ipv6' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/bsd/x86/shell_reverse_tcp_ipv6'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/x86/shell_reverse_tcp_ipv6'
  end

  context 'bsdi/x86/shell/bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/bsdi/x86/bind_tcp',
                              'stages/bsdi/x86/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'bsdi/x86/shell/bind_tcp'
  end

  context 'bsdi/x86/shell/reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/bsdi/x86/reverse_tcp',
                              'stages/bsdi/x86/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'bsdi/x86/shell/reverse_tcp'
  end

  context 'bsdi/x86/shell_bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/bsdi/x86/shell_bind_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'bsdi/x86/shell_bind_tcp'
  end

  context 'bsdi/x86/shell_find_port' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/bsdi/x86/shell_find_port'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'bsdi/x86/shell_find_port'
  end

  context 'bsdi/x86/shell_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/bsdi/x86/shell_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'bsdi/x86/shell_reverse_tcp'
  end

  context 'cmd/mainframe/generic_jcl' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/mainframe/generic_jcl'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/mainframe/generic_jcl'
  end

  context 'cmd/mainframe/bind_shell_jcl' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/mainframe/bind_shell_jcl'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/mainframe/bind_shell_jcl'
  end

  context 'cmd/mainframe/reverse_shell_jcl' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/mainframe/reverse_shell_jcl'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/mainframe/reverse_shell_jcl'
  end

  context 'cmd/mainframe/apf_privesc_jcl' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/mainframe/apf_privesc_jcl'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/mainframe/apf_privesc_jcl'
  end

  context 'cmd/unix/bind_awk' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/bind_awk'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/bind_awk'
  end

  context 'cmd/unix/bind_busybox_telnetd' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/bind_busybox_telnetd'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/bind_busybox_telnetd'
  end

  context 'cmd/unix/bind_inetd' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/bind_inetd'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/bind_inetd'
  end

  context 'cmd/unix/bind_lua' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/bind_lua'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/bind_lua'
  end

  context 'cmd/unix/bind_jjs' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/bind_jjs'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/bind_jjs'
  end

  context 'cmd/unix/bind_netcat' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/bind_netcat'
                          ],
                          dynamic_size: true,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/bind_netcat'
  end

  context 'cmd/unix/bind_netcat_gaping' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/bind_netcat_gaping'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/bind_netcat_gaping'
  end

  context 'cmd/unix/bind_netcat_gaping_ipv6' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/bind_netcat_gaping_ipv6'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/bind_netcat_gaping_ipv6'
  end

  context 'cmd/unix/bind_nodejs' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/bind_nodejs'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/bind_nodejs'
  end

  context 'cmd/unix/bind_socat_udp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/bind_socat_udp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/bind_socat_udp'
  end

  context 'cmd/unix/bind_perl' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/bind_perl'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/bind_perl'
  end

  context 'cmd/unix/bind_perl_ipv6' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/bind_perl_ipv6'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/bind_perl_ipv6'
  end

  context 'cmd/unix/bind_r' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/cmd/unix/bind_r'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/bind_r'
  end

  context 'cmd/unix/bind_ruby' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/bind_ruby'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/bind_ruby'
  end

  context 'cmd/unix/bind_ruby_ipv6' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/bind_ruby_ipv6'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/bind_ruby_ipv6'
  end

  context 'cmd/unix/bind_stub' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/bind_stub'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/bind_stub'
  end

  context 'cmd/unix/bind_zsh' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/bind_zsh'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/bind_zsh'
  end

  context 'cmd/unix/generic' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/generic'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/generic'
  end

  context 'cmd/unix/interact' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/interact'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/interact'
  end

  context 'cmd/unix/reverse' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse'
  end

  context 'cmd/unix/reverse_awk' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse_awk'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_awk'
  end

  context 'cmd/unix/reverse_bash' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse_bash'
                          ],
                          dynamic_size: true,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_bash'
  end

  context 'cmd/unix/reverse_bash_udp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/cmd/unix/reverse_bash_udp'
                          ],
                          dynamic_size: true,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_bash_udp'
  end

  context 'cmd/unix/reverse_bash_telnet_ssl' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse_bash_telnet_ssl'
                          ],
                          dynamic_size: true,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_bash_telnet_ssl'
  end

  context 'cmd/unix/reverse_ksh' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse_ksh'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_ksh'
  end

  context 'cmd/unix/reverse_jjs' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse_jjs'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_jjs'
  end

  context 'cmd/unix/reverse_lua' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse_lua'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_lua'
  end

  context 'cmd/unix/reverse_ncat_ssl' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/cmd/unix/reverse_ncat_ssl'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_ncat_ssl'
  end

  context 'cmd/unix/reverse_netcat' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse_netcat'
                          ],
                          dynamic_size: true,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_netcat'
  end

  context 'cmd/unix/reverse_netcat_gaping' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse_netcat_gaping'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_netcat_gaping'
  end

  context 'cmd/unix/reverse_nodejs' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse_nodejs'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_nodejs'
  end

  context 'cmd/unix/reverse_openssl' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse_openssl'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_openssl'
  end

  context 'cmd/unix/reverse_socat_udp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse_socat_udp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_socat_udp'
  end

  context 'cmd/unix/reverse_perl' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse_perl'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_perl'
  end

  context 'cmd/unix/reverse_perl_ssl' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse_perl_ssl'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_perl_ssl'
  end

  context 'cmd/unix/reverse_php_ssl' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse_php_ssl'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_php_ssl'
  end

  context 'cmd/unix/reverse_python' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse_python'
                          ],
                          dynamic_size: true,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_python'
  end

  context 'cmd/unix/reverse_python_ssl' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse_python_ssl'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_python_ssl'
  end

  context 'cmd/unix/reverse_r' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/cmd/unix/reverse_r'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_r'
  end

  context 'cmd/unix/reverse_ruby' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse_ruby'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_ruby'
  end

  context 'cmd/unix/reverse_ruby_ssl' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse_ruby_ssl'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_ruby_ssl'
  end

  context 'cmd/unix/reverse_ssl_double_telnet' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse_ssl_double_telnet'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_ssl_double_telnet'
  end

  context 'cmd/unix/reverse_stub' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse_stub'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_stub'
  end

  context 'cmd/unix/reverse_zsh' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse_zsh'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_zsh'
  end

  context 'cmd/windows/adduser' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/windows/adduser'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/windows/adduser'
  end

  context 'cmd/windows/bind_lua' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/windows/bind_lua'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/windows/bind_lua'
  end

  context 'cmd/windows/bind_perl' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/windows/bind_perl'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/windows/bind_perl'
  end

  context 'cmd/windows/bind_perl_ipv6' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/windows/bind_perl_ipv6'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/windows/bind_perl_ipv6'
  end

  context 'cmd/windows/bind_ruby' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/windows/bind_ruby'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/windows/bind_ruby'
  end

  context 'cmd/windows/download_eval_vbs' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/windows/download_eval_vbs'
                          ],
                          dynamic_size: true,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/windows/download_eval_vbs'
  end

  context 'cmd/windows/download_exec_vbs' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/windows/download_exec_vbs'
                          ],
                          dynamic_size: true,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/windows/download_exec_vbs'
  end

  context 'cmd/windows/generic' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/windows/generic'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/windows/generic'
  end

  context 'cmd/windows/powershell_bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/windows/powershell_bind_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/windows/powershell_bind_tcp'
  end

  context 'cmd/windows/powershell_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/windows/powershell_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/windows/powershell_reverse_tcp'
  end

  context 'cmd/windows/reverse_lua' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/windows/reverse_lua'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/windows/reverse_lua'
  end

  context 'cmd/windows/reverse_perl' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/windows/reverse_perl'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/windows/reverse_perl'
  end

  context 'cmd/windows/reverse_powershell' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/windows/reverse_powershell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/windows/reverse_powershell'
  end

  context 'cmd/windows/reverse_ruby' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/cmd/windows/reverse_ruby'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/windows/reverse_ruby'
  end

  context 'firefox/exec' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/firefox/exec'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'firefox/exec'
  end

  context 'firefox/shell_bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/firefox/shell_bind_tcp'
                          ],
                          dynamic_size: true,
                          modules_pathname: modules_pathname,
                          reference_name: 'firefox/shell_bind_tcp'
  end

  context 'firefox/shell_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/firefox/shell_reverse_tcp'
                          ],
                          dynamic_size: true,
                          modules_pathname: modules_pathname,
                          reference_name: 'firefox/shell_reverse_tcp'
  end

  context 'generic/custom' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/generic/custom'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'generic/custom'
  end

  context 'generic/debug_trap' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/generic/debug_trap'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'generic/debug_trap'
  end

  context 'generic/shell_bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/generic/shell_bind_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'generic/shell_bind_tcp'
  end

  context 'generic/shell_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/generic/shell_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'generic/shell_reverse_tcp'
  end

  context 'generic/tight_loop' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/generic/tight_loop'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'generic/tight_loop'
  end

  context 'java/jsp_shell_bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/java/jsp_shell_bind_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'java/jsp_shell_bind_tcp'
  end

  context 'java/jsp_shell_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/java/jsp_shell_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'java/jsp_shell_reverse_tcp'
  end

  context 'java/meterpreter/bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/java/bind_tcp',
                              'stages/java/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'java/meterpreter/bind_tcp'
  end

  context 'java/meterpreter/reverse_http' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/java/reverse_http',
                              'stages/java/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'java/meterpreter/reverse_http'
  end

  context 'java/meterpreter/reverse_https' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/java/reverse_https',
                              'stages/java/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'java/meterpreter/reverse_https'
  end

  context 'java/meterpreter/reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/java/reverse_tcp',
                              'stages/java/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'java/meterpreter/reverse_tcp'
  end

  context 'java/shell/bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/java/bind_tcp',
                              'stages/java/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'java/shell/bind_tcp'
  end

  context 'java/shell/reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/java/reverse_tcp',
                              'stages/java/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'java/shell/reverse_tcp'
  end

  context 'java/shell_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/java/shell_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'java/shell_reverse_tcp'
  end

  context 'linux/aarch64/shell_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/linux/aarch64/shell_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/aarch64/shell_reverse_tcp'
  end

  context 'linux/aarch64/meterpreter_reverse_http' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/linux/aarch64/meterpreter_reverse_http'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/aarch64/meterpreter_reverse_http'
  end

  context 'linux/aarch64/meterpreter_reverse_https' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/linux/aarch64/meterpreter_reverse_https'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/aarch64/meterpreter_reverse_https'
  end

  context 'linux/aarch64/shell/reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/linux/aarch64/reverse_tcp',
                            'stages/linux/aarch64/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/aarch64/shell/reverse_tcp'
  end


  context 'linux/armbe/shell_bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/armbe/shell_bind_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/armbe/shell_bind_tcp'
  end

  context 'linux/armle/adduser' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/armle/adduser'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/armle/adduser'
  end

  context 'linux/armle/exec' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/armle/exec'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/armle/exec'
  end

  context 'linux/armle/shell/bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/linux/armle/bind_tcp',
                              'stages/linux/armle/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/armle/shell/bind_tcp'
  end

  context 'linux/armle/shell/reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/linux/armle/reverse_tcp',
                              'stages/linux/armle/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/armle/shell/reverse_tcp'
  end

  context 'linux/armle/shell_bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/armle/shell_bind_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/armle/shell_bind_tcp'
  end

  context 'linux/armle/shell_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/armle/shell_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/armle/shell_reverse_tcp'
  end

  context 'linux/mipsbe/exec' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/mipsbe/exec'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/mipsbe/exec'
  end

  context 'linux/mipsbe/reboot' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/mipsbe/reboot'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/mipsbe/reboot'
  end

  context 'linux/mipsbe/shell/reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/linux/mipsbe/reverse_tcp',
                              'stages/linux/mipsbe/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/mipsbe/shell/reverse_tcp'
  end

  context 'linux/mipsbe/shell_bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/mipsbe/shell_bind_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/mipsbe/shell_bind_tcp'
  end

  context 'linux/mipsbe/shell_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/mipsbe/shell_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/mipsbe/shell_reverse_tcp'
  end

  context 'linux/mipsle/exec' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/mipsle/exec'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/mipsle/exec'
  end

  context 'linux/mipsle/reboot' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/mipsle/reboot'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/mipsle/reboot'
  end

  context 'linux/mipsle/shell/reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/linux/mipsle/reverse_tcp',
                              'stages/linux/mipsle/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/mipsle/shell/reverse_tcp'
  end

  context 'linux/mipsle/shell_bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/mipsle/shell_bind_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/mipsle/shell_bind_tcp'
  end

  context 'linux/mipsle/shell_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/mipsle/shell_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/mipsle/shell_reverse_tcp'
  end

  context 'linux/ppc/shell_bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/ppc/shell_bind_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/ppc/shell_bind_tcp'
  end

  context 'linux/ppc/shell_find_port' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/ppc/shell_find_port'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/ppc/shell_find_port'
  end

  context 'linux/ppc/shell_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/ppc/shell_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/ppc/shell_reverse_tcp'
  end

  context 'linux/ppc64/shell_bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/ppc64/shell_bind_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/ppc64/shell_bind_tcp'
  end

  context 'linux/ppc64/shell_find_port' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/ppc64/shell_find_port'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/ppc64/shell_find_port'
  end

  context 'linux/ppc64/shell_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/ppc64/shell_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/ppc64/shell_reverse_tcp'
  end

  context 'linux/x64/exec' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/x64/exec'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x64/exec'
  end

  context 'linux/x64/shell/bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/linux/x64/bind_tcp',
                              'stages/linux/x64/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x64/shell/bind_tcp'
  end

  context 'linux/x64/shell/reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/linux/x64/reverse_tcp',
                              'stages/linux/x64/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x64/shell/reverse_tcp'
  end

  context 'linux/x64/shell_bind_ipv6_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/x64/shell_bind_ipv6_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x64/shell_bind_ipv6_tcp'
  end

  context 'linux/x64/shell_bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/x64/shell_bind_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x64/shell_bind_tcp'
  end

  context 'linux/x64/shell_bind_tcp_random_port' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/x64/shell_bind_tcp_random_port'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x64/shell_bind_tcp_random_port'
  end

  context 'linux/x64/shell_find_port' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/x64/shell_find_port'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x64/shell_find_port'
  end

  context 'linux/x64/shell_reverse_ipv6_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/x64/shell_reverse_ipv6_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x64/shell_reverse_ipv6_tcp'
  end

  context 'linux/x64/shell_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/x64/shell_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x64/shell_reverse_tcp'
  end

  context 'linux/x86/adduser' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/x86/adduser'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/adduser'
  end

  context 'linux/x86/chmod' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/x86/chmod'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/chmod'
  end

  context 'linux/x86/exec' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/x86/exec'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/exec'
  end

  context 'linux/x86/read_file' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/x86/read_file'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/read_file'
  end

  context 'linux/x86/shell/bind_ipv6_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/linux/x86/bind_ipv6_tcp',
                              'stages/linux/x86/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/shell/bind_ipv6_tcp'
  end

  context 'linux/x86/shell/bind_nonx_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/linux/x86/bind_nonx_tcp',
                              'stages/linux/x86/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/shell/bind_nonx_tcp'
  end

  context 'linux/x86/shell/bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/linux/x86/bind_tcp',
                              'stages/linux/x86/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/shell/bind_tcp'
  end

  context 'linux/x86/shell/find_tag' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/linux/x86/find_tag',
                              'stages/linux/x86/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/shell/find_tag'
  end

  context 'linux/x86/shell/reverse_ipv6_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/linux/x86/reverse_ipv6_tcp',
                              'stages/linux/x86/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/shell/reverse_ipv6_tcp'
  end

  context 'linux/x86/shell/reverse_nonx_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/linux/x86/reverse_nonx_tcp',
                              'stages/linux/x86/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/shell/reverse_nonx_tcp'
  end

  context 'linux/x86/shell/reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/linux/x86/reverse_tcp',
                              'stages/linux/x86/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/shell/reverse_tcp'
  end

  context 'linux/x86/shell_bind_ipv6_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/x86/shell_bind_ipv6_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/shell_bind_ipv6_tcp'
  end

  context 'linux/x86/shell_bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/x86/shell_bind_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/shell_bind_tcp'
  end

  context 'linux/x86/shell_bind_tcp_random_port' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/x86/shell_bind_tcp_random_port'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/shell_bind_tcp_random_port'
  end

  context 'linux/x86/shell_find_port' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/x86/shell_find_port'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/shell_find_port'
  end

  context 'linux/x86/shell_find_tag' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/x86/shell_find_tag'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/shell_find_tag'
  end

  context 'linux/x86/shell_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/x86/shell_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/shell_reverse_tcp'
  end

  context 'linux/x86/shell_reverse_tcp_ipv6' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/x86/shell_reverse_tcp_ipv6'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/shell_reverse_tcp_ipv6'
  end

  context 'mainframe/shell_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/mainframe/shell_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'mainframe/shell_reverse_tcp'
  end

  context 'multi/meterpreter/reverse_http' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/multi/reverse_http',
                            'stages/multi/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'multi/meterpreter/reverse_http'
  end

  context 'multi/meterpreter/reverse_https' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/multi/reverse_https',
                            'stages/multi/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'multi/meterpreter/reverse_https'
  end

  context 'netware/shell/reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/netware/reverse_tcp',
                              'stages/netware/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'netware/shell/reverse_tcp'
  end

  context 'nodejs/shell_bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/nodejs/shell_bind_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'nodejs/shell_bind_tcp'
  end

  context 'nodejs/shell_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/nodejs/shell_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'nodejs/shell_reverse_tcp'
  end

  context 'nodejs/shell_reverse_tcp_ssl' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/nodejs/shell_reverse_tcp_ssl'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'nodejs/shell_reverse_tcp_ssl'
  end

  context 'osx/armle/execute/bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/osx/armle/bind_tcp',
                              'stages/osx/armle/execute'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/armle/execute/bind_tcp'
  end

  context 'osx/armle/execute/reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/osx/armle/reverse_tcp',
                              'stages/osx/armle/execute'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/armle/execute/reverse_tcp'
  end

  context 'osx/armle/shell/bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/osx/armle/bind_tcp',
                              'stages/osx/armle/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/armle/shell/bind_tcp'
  end

  context 'osx/armle/shell/reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/osx/armle/reverse_tcp',
                              'stages/osx/armle/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/armle/shell/reverse_tcp'
  end

  context 'osx/armle/shell_bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/osx/armle/shell_bind_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/armle/shell_bind_tcp'
  end

  context 'osx/armle/shell_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/osx/armle/shell_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/armle/shell_reverse_tcp'
  end

  context 'osx/armle/vibrate' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/osx/armle/vibrate'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/armle/vibrate'
  end

  context 'osx/ppc/shell/bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/osx/ppc/bind_tcp',
                              'stages/osx/ppc/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/ppc/shell/bind_tcp'
  end

  context 'osx/ppc/shell/find_tag' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/osx/ppc/find_tag',
                              'stages/osx/ppc/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/ppc/shell/find_tag'
  end

  context 'osx/ppc/shell/reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/osx/ppc/reverse_tcp',
                              'stages/osx/ppc/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/ppc/shell/reverse_tcp'
  end

  context 'osx/ppc/shell_bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/osx/ppc/shell_bind_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/ppc/shell_bind_tcp'
  end

  context 'osx/ppc/shell_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/osx/ppc/shell_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/ppc/shell_reverse_tcp'
  end

  context 'osx/x64/dupandexecve/bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/osx/x64/bind_tcp',
                              'stages/osx/x64/dupandexecve'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x64/dupandexecve/bind_tcp'
  end

  context 'osx/x64/dupandexecve/reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/osx/x64/reverse_tcp',
                              'stages/osx/x64/dupandexecve'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x64/dupandexecve/reverse_tcp'
  end

  context 'osx/x64/exec' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/osx/x64/exec'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x64/exec'
  end

  context 'osx/x64/meterpreter/bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/osx/x64/bind_tcp',
                              'stages/osx/x64/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x64/meterpreter/bind_tcp'
  end

  context 'osx/x64/meterpreter/reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/osx/x64/reverse_tcp',
                              'stages/osx/x64/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x64/meterpreter/reverse_tcp'
  end

  context 'osx/x64/meterpreter_reverse_http' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/osx/x64/meterpreter_reverse_http'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x64/meterpreter_reverse_http'
  end

  context 'osx/x64/meterpreter_reverse_https' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/osx/x64/meterpreter_reverse_https'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x64/meterpreter_reverse_https'
  end

  context 'osx/x64/meterpreter_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/osx/x64/meterpreter_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x64/meterpreter_reverse_tcp'
  end

  context 'osx/x64/say' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/osx/x64/say'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x64/say'
  end

  context 'osx/x64/shell_bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/osx/x64/shell_bind_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x64/shell_bind_tcp'
  end

  context 'osx/x64/shell_find_tag' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/osx/x64/shell_find_tag'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x64/shell_find_tag'
  end

  context 'osx/x64/shell_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/osx/x64/shell_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x64/shell_reverse_tcp'
  end

  context 'osx/x86/bundleinject/bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/osx/x86/bind_tcp',
                              'stages/osx/x86/bundleinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x86/bundleinject/bind_tcp'
  end

  context 'osx/x86/bundleinject/reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/osx/x86/reverse_tcp',
                              'stages/osx/x86/bundleinject',
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x86/bundleinject/reverse_tcp'
  end

  context 'osx/x86/exec' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/osx/x86/exec'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x86/exec'
  end

  context 'osx/x86/isight/bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/osx/x86/bind_tcp',
                              'stages/osx/x86/isight'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x86/isight/bind_tcp'
  end

  context 'osx/x86/isight/reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/osx/x86/reverse_tcp',
                              'stages/osx/x86/isight'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x86/isight/reverse_tcp'
  end

  context 'osx/x86/shell_bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/osx/x86/shell_bind_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x86/shell_bind_tcp'
  end

  context 'osx/x86/shell_find_port' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/osx/x86/shell_find_port'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x86/shell_find_port'
  end

  context 'osx/x86/shell_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/osx/x86/shell_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x86/shell_reverse_tcp'
  end

  context 'osx/x86/vforkshell/bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/osx/x86/bind_tcp',
                              'stages/osx/x86/vforkshell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x86/vforkshell/bind_tcp'
  end

  context 'osx/x86/vforkshell/reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/osx/x86/reverse_tcp',
                              'stages/osx/x86/vforkshell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x86/vforkshell/reverse_tcp'
  end

  context 'osx/x86/vforkshell_bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/osx/x86/vforkshell_bind_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x86/vforkshell_bind_tcp'
  end

  context 'osx/x86/vforkshell_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/osx/x86/vforkshell_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x86/vforkshell_reverse_tcp'
  end

  context 'php/bind_perl' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/php/bind_perl'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'php/bind_perl'
  end

  context 'php/bind_perl_ipv6' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/php/bind_perl_ipv6'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'php/bind_perl_ipv6'
  end

  context 'php/bind_php' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/php/bind_php'
                          ],
                          dynamic_size: true,
                          modules_pathname: modules_pathname,
                          reference_name: 'php/bind_php'
  end

  context 'php/bind_php_ipv6' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/php/bind_php_ipv6'
                          ],
                          dynamic_size: true,
                          modules_pathname: modules_pathname,
                          reference_name: 'php/bind_php_ipv6'
  end

  context 'php/download_exec' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/php/download_exec'
                          ],
                          dynamic_size: true,
                          modules_pathname: modules_pathname,
                          reference_name: 'php/download_exec'
  end

  context 'php/exec' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/php/exec'
                          ],
                          dynamic_size: true,
                          modules_pathname: modules_pathname,
                          reference_name: 'php/exec'
  end

  context 'php/meterpreter/bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/php/bind_tcp',
                              'stages/php/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'php/meterpreter/bind_tcp'
  end

  context 'php/meterpreter/bind_tcp_uuid' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/php/bind_tcp_uuid',
                              'stages/php/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'php/meterpreter/bind_tcp_uuid'
  end

  context 'php/meterpreter/bind_tcp_ipv6' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/php/bind_tcp_ipv6',
                              'stages/php/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'php/meterpreter/bind_tcp_ipv6'
  end

  context 'php/meterpreter/bind_tcp_ipv6_uuid' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/php/bind_tcp_ipv6_uuid',
                              'stages/php/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'php/meterpreter/bind_tcp_ipv6_uuid'
  end

  context 'php/meterpreter/reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/php/reverse_tcp',
                              'stages/php/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'php/meterpreter/reverse_tcp'
  end

  context 'php/meterpreter/reverse_tcp_uuid' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/php/reverse_tcp_uuid',
                              'stages/php/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'php/meterpreter/reverse_tcp_uuid'
  end

  context 'php/meterpreter_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/php/meterpreter_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'php/meterpreter_reverse_tcp'
  end

  context 'php/reverse_perl' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/php/reverse_perl'
                          ],
                          dynamic_size: true,
                          modules_pathname: modules_pathname,
                          reference_name: 'php/reverse_perl'
  end

  context 'php/reverse_php' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/php/reverse_php'
                          ],
                          dynamic_size: true,
                          modules_pathname: modules_pathname,
                          reference_name: 'php/reverse_php'
  end

  context 'php/shell_findsock' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/php/shell_findsock'
                          ],
                          dynamic_size: true,
                          modules_pathname: modules_pathname,
                          reference_name: 'php/shell_findsock'
  end

  context 'python/meterpreter/bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/python/bind_tcp',
                              'stages/python/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'python/meterpreter/bind_tcp'
  end

  context 'python/meterpreter/bind_tcp_uuid' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/python/bind_tcp_uuid',
                              'stages/python/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'python/meterpreter/bind_tcp_uuid'
  end

  context 'python/meterpreter/reverse_http' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/python/reverse_http',
                            'stages/python/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'python/meterpreter/reverse_http'
  end

  context 'python/meterpreter/reverse_https' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/python/reverse_https',
                            'stages/python/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'python/meterpreter/reverse_https'
  end

  context 'python/meterpreter/reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/python/reverse_tcp',
                              'stages/python/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'python/meterpreter/reverse_tcp'
  end

  context 'python/meterpreter/reverse_tcp_ssl' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/python/reverse_tcp_ssl',
                            'stages/python/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'python/meterpreter/reverse_tcp_ssl'
  end

  context 'python/meterpreter/reverse_tcp_uuid' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/python/reverse_tcp_uuid',
                              'stages/python/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'python/meterpreter/reverse_tcp_uuid'
  end

  context 'python/meterpreter_bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/python/meterpreter_bind_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'python/meterpreter_bind_tcp'
  end

  context 'python/meterpreter_reverse_http' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/python/meterpreter_reverse_http'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'python/meterpreter_reverse_http'
  end

  context 'python/meterpreter_reverse_https' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/python/meterpreter_reverse_https'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'python/meterpreter_reverse_https'
  end

  context 'python/meterpreter_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/python/meterpreter_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'python/meterpreter_reverse_tcp'
  end

  context 'python/shell_bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/python/shell_bind_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'python/shell_bind_tcp'
  end

  context 'python/shell_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/python/shell_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'python/shell_reverse_tcp'
  end

  context 'python/shell_reverse_tcp_ssl' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/python/shell_reverse_tcp_ssl'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'python/shell_reverse_tcp_ssl'
  end

  context 'python/shell_reverse_udp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/python/shell_reverse_udp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'python/shell_reverse_udp'
  end

  context 'ruby/shell_bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/ruby/shell_bind_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'ruby/shell_bind_tcp'
  end

  context 'ruby/shell_bind_tcp_ipv6' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/ruby/shell_bind_tcp_ipv6'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'ruby/shell_bind_tcp_ipv6'
  end

  context 'ruby/shell_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/ruby/shell_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'ruby/shell_reverse_tcp'
  end

  context 'ruby/shell_reverse_tcp_ssl' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/ruby/shell_reverse_tcp_ssl'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'ruby/shell_reverse_tcp_ssl'
  end

  context 'solaris/sparc/shell_bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/solaris/sparc/shell_bind_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'solaris/sparc/shell_bind_tcp'
  end

  context 'solaris/sparc/shell_find_port' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/solaris/sparc/shell_find_port'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'solaris/sparc/shell_find_port'
  end

  context 'solaris/sparc/shell_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/solaris/sparc/shell_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'solaris/sparc/shell_reverse_tcp'
  end

  context 'solaris/x86/shell_bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/solaris/x86/shell_bind_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'solaris/x86/shell_bind_tcp'
  end

  context 'solaris/x86/shell_find_port' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/solaris/x86/shell_find_port'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'solaris/x86/shell_find_port'
  end

  context 'solaris/x86/shell_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/solaris/x86/shell_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'solaris/x86/shell_reverse_tcp'
  end

  context 'tty/unix/interact' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/tty/unix/interact'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'tty/unix/interact'
  end

  context 'windows/adduser' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/windows/adduser'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/adduser'
  end

  context 'windows/dllinject/bind_ipv6_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/bind_ipv6_tcp',
                              'stages/windows/dllinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/dllinject/bind_ipv6_tcp'
  end

  context 'windows/dllinject/bind_named_pipe' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/windows/bind_named_pipe',
                            'stages/windows/dllinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/dllinject/bind_named_pipe'
  end

  context 'windows/dllinject/bind_nonx_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/bind_nonx_tcp',
                              'stages/windows/dllinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/dllinject/bind_nonx_tcp'
  end

  context 'windows/dllinject/bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/bind_tcp',
                              'stages/windows/dllinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/dllinject/bind_tcp'
  end

  context 'windows/dllinject/bind_tcp_rc4' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/bind_tcp_rc4',
                              'stages/windows/dllinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/dllinject/bind_tcp_rc4'
  end

  context 'windows/dllinject/find_tag' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/findtag_ord',
                              'stages/windows/dllinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/dllinject/find_tag'
  end

  context 'windows/dllinject/reverse_hop_http' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_hop_http',
                              'stages/windows/dllinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/dllinject/reverse_hop_http'
  end

  context 'windows/dllinject/reverse_http' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_http',
                              'stages/windows/dllinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/dllinject/reverse_http'
  end

  context 'windows/dllinject/reverse_http_proxy_pstore' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/windows/reverse_http_proxy_pstore',
                            'stages/windows/dllinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/dllinject/reverse_http_proxy_pstore'
  end

  context 'windows/dllinject/reverse_ipv6_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_ipv6_tcp',
                              'stages/windows/dllinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/dllinject/reverse_ipv6_tcp'
  end

  context 'windows/dllinject/reverse_nonx_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_nonx_tcp',
                              'stages/windows/dllinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/dllinject/reverse_nonx_tcp'
  end

  context 'windows/dllinject/reverse_ord_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_ord_tcp',
                              'stages/windows/dllinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/dllinject/reverse_ord_tcp'
  end

  context 'windows/dllinject/reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp',
                              'stages/windows/dllinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/dllinject/reverse_tcp'
  end

  context 'windows/dllinject/reverse_tcp_allports' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_allports',
                              'stages/windows/dllinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/dllinject/reverse_tcp_allports'
  end

  context 'windows/dllinject/reverse_tcp_dns' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_dns',
                              'stages/windows/dllinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/dllinject/reverse_tcp_dns'
  end

  context 'windows/dllinject/reverse_tcp_rc4' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_rc4',
                              'stages/windows/dllinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/dllinject/reverse_tcp_rc4'
  end

  context 'windows/dllinject/reverse_tcp_rc4_dns' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_rc4_dns',
                              'stages/windows/dllinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/dllinject/reverse_tcp_rc4_dns'
  end

  context 'windows/dns_txt_query_exec' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/windows/dns_txt_query_exec'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/dns_txt_query_exec'
  end

  context 'windows/download_exec' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/windows/download_exec'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/download_exec'
  end

  context 'windows/encrypted_shell_reverse_tcp' do
    it_should_behave_like 'payload is not cached',
                          ancestor_reference_names: [
                              'singles/windows/encrypted_shell_reverse_tcp',
                              'stagers/windows/encrypted_reverse_tcp',
                              'stages/windows/encrypted_shell'
                          ],
                          reference_name: 'windows/encrypted_shell_reverse_tcp'
  end

  context 'windows/exec' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/windows/exec'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/exec'
  end

  context 'windows/format_all_drives' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/windows/format_all_drives'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/format_all_drives'
  end

  context 'windows/loadlibrary' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/windows/loadlibrary'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/loadlibrary'
  end

  context 'windows/messagebox' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/windows/messagebox'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/messagebox'
  end

  context 'windows/meterpreter_bind_named_pipe' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/windows/meterpreter_bind_named_pipe'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter_bind_named_pipe'
  end

  context 'windows/meterpreter_bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/windows/meterpreter_bind_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter_bind_tcp'
  end

  context 'windows/meterpreter_reverse_http' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/windows/meterpreter_reverse_http'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter_reverse_http'
  end

  context 'windows/meterpreter_reverse_https' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/windows/meterpreter_reverse_https'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter_reverse_https'
  end

  context 'windows/meterpreter_reverse_ipv6_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/windows/meterpreter_reverse_ipv6_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter_reverse_ipv6_tcp'
  end

  context 'windows/meterpreter_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/windows/meterpreter_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter_reverse_tcp'
  end

  context 'windows/meterpreter/bind_ipv6_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/bind_ipv6_tcp',
                              'stages/windows/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/bind_ipv6_tcp'
  end

  context 'windows/meterpreter/bind_ipv6_tcp_uuid' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/bind_ipv6_tcp_uuid',
                              'stages/windows/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/bind_ipv6_tcp_uuid'
  end

  context 'windows/meterpreter/bind_named_pipe' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/windows/bind_named_pipe',
                            'stages/windows/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/bind_named_pipe'
  end

  context 'windows/meterpreter/bind_nonx_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/bind_nonx_tcp',
                              'stages/windows/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/bind_nonx_tcp'
  end

  context 'windows/meterpreter/bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/bind_tcp',
                              'stages/windows/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/bind_tcp'
  end

  context 'windows/meterpreter/bind_tcp_rc4' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/bind_tcp_rc4',
                              'stages/windows/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/bind_tcp_rc4'
  end

  context 'windows/meterpreter/bind_tcp_uuid' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/bind_tcp_uuid',
                              'stages/windows/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/bind_tcp_uuid'
  end

  context 'windows/meterpreter/find_tag' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/findtag_ord',
                              'stages/windows/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/find_tag'
  end

  context 'windows/meterpreter/reverse_hop_http' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_hop_http',
                              'stages/windows/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/reverse_hop_http'
  end

  context 'windows/meterpreter/reverse_http' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_http',
                              'stages/windows/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/reverse_http'
  end

  context 'windows/meterpreter/reverse_http_proxy_pstore' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/windows/reverse_http_proxy_pstore',
                            'stages/windows/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/reverse_http_proxy_pstore'
  end

  context 'windows/meterpreter/reverse_https' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_https',
                              'stages/windows/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/reverse_https'
  end

  context 'windows/meterpreter/reverse_https_proxy' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_https_proxy',
                              'stages/windows/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/reverse_https_proxy'
  end

  context 'windows/meterpreter/reverse_ipv6_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_ipv6_tcp',
                              'stages/windows/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/reverse_ipv6_tcp'
  end

  context 'windows/meterpreter/reverse_named_pipe' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_named_pipe',
                              'stages/windows/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/reverse_named_pipe'
  end

  context 'windows/meterpreter/reverse_nonx_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_nonx_tcp',
                              'stages/windows/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/reverse_nonx_tcp'
  end

  context 'windows/meterpreter/reverse_ord_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_ord_tcp',
                              'stages/windows/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/reverse_ord_tcp'
  end

  context 'windows/meterpreter/reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp',
                              'stages/windows/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/reverse_tcp'
  end

  context 'windows/meterpreter/reverse_tcp_allports' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_allports',
                              'stages/windows/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/reverse_tcp_allports'
  end

  context 'windows/meterpreter/reverse_tcp_dns' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_dns',
                              'stages/windows/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/reverse_tcp_dns'
  end

  context 'windows/meterpreter/reverse_tcp_rc4' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_rc4',
                              'stages/windows/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/reverse_tcp_rc4'
  end

  context 'windows/meterpreter/reverse_tcp_rc4_dns' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_rc4_dns',
                              'stages/windows/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/reverse_tcp_rc4_dns'
  end

  context 'windows/meterpreter/reverse_tcp_uuid' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_uuid',
                              'stages/windows/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/reverse_tcp_uuid'
  end

  context 'windows/metsvc_bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/windows/metsvc_bind_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/metsvc_bind_tcp'
  end

  context 'windows/metsvc_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/windows/metsvc_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/metsvc_reverse_tcp'
  end

  context 'windows/patchupdllinject/bind_ipv6_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/bind_ipv6_tcp',
                              'stages/windows/patchupdllinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupdllinject/bind_ipv6_tcp'
  end

  context 'windows/patchupdllinject/bind_named_pipe' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/windows/bind_named_pipe',
                            'stages/windows/patchupdllinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupdllinject/bind_named_pipe'
  end

  context 'windows/patchupdllinject/bind_nonx_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/bind_nonx_tcp',
                              'stages/windows/patchupdllinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupdllinject/bind_nonx_tcp'
  end

  context 'windows/patchupdllinject/bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/bind_tcp',
                              'stages/windows/patchupdllinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupdllinject/bind_tcp'
  end

  context 'windows/patchupdllinject/bind_tcp_rc4' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/bind_tcp_rc4',
                              'stages/windows/patchupdllinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupdllinject/bind_tcp_rc4'
  end

  context 'windows/patchupdllinject/find_tag' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/findtag_ord',
                              'stages/windows/patchupdllinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupdllinject/find_tag'
  end

  context 'windows/patchupdllinject/reverse_ipv6_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_ipv6_tcp',
                              'stages/windows/patchupdllinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupdllinject/reverse_ipv6_tcp'
  end

  context 'windows/patchupdllinject/reverse_nonx_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_nonx_tcp',
                              'stages/windows/patchupdllinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupdllinject/reverse_nonx_tcp'
  end

  context 'windows/patchupdllinject/reverse_ord_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_ord_tcp',
                              'stages/windows/patchupdllinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupdllinject/reverse_ord_tcp'
  end

  context 'windows/patchupdllinject/reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp',
                              'stages/windows/patchupdllinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupdllinject/reverse_tcp'
  end

  context 'windows/patchupdllinject/reverse_tcp_allports' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_allports',
                              'stages/windows/patchupdllinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupdllinject/reverse_tcp_allports'
  end

  context 'windows/patchupdllinject/reverse_tcp_dns' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_dns',
                              'stages/windows/patchupdllinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupdllinject/reverse_tcp_dns'
  end

  context 'windows/patchupdllinject/reverse_tcp_rc4' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_rc4',
                              'stages/windows/patchupdllinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupdllinject/reverse_tcp_rc4'
  end

  context 'windows/patchupdllinject/reverse_tcp_rc4_dns' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_rc4_dns',
                              'stages/windows/patchupdllinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupdllinject/reverse_tcp_rc4_dns'
  end

  context 'windows/patchupmeterpreter/bind_ipv6_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/bind_ipv6_tcp',
                              'stages/windows/patchupmeterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupmeterpreter/bind_ipv6_tcp'
  end

  context 'windows/patchupmeterpreter/bind_named_pipe' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/windows/bind_named_pipe',
                            'stages/windows/patchupmeterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupmeterpreter/bind_named_pipe'
  end

  context 'windows/patchupmeterpreter/bind_nonx_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/bind_nonx_tcp',
                              'stages/windows/patchupmeterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupmeterpreter/bind_nonx_tcp'
  end

  context 'windows/patchupmeterpreter/bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/bind_tcp',
                              'stages/windows/patchupmeterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupmeterpreter/bind_tcp'
  end

  context 'windows/patchupmeterpreter/bind_tcp_rc4' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/bind_tcp_rc4',
                              'stages/windows/patchupmeterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupmeterpreter/bind_tcp_rc4'
  end

  context 'windows/patchupmeterpreter/find_tag' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/findtag_ord',
                              'stages/windows/patchupmeterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupmeterpreter/find_tag'
  end

  context 'windows/patchupmeterpreter/reverse_ipv6_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_ipv6_tcp',
                              'stages/windows/patchupmeterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupmeterpreter/reverse_ipv6_tcp'
  end

  context 'windows/patchupmeterpreter/reverse_nonx_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_nonx_tcp',
                              'stages/windows/patchupmeterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupmeterpreter/reverse_nonx_tcp'
  end

  context 'windows/patchupmeterpreter/reverse_ord_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_ord_tcp',
                              'stages/windows/patchupmeterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupmeterpreter/reverse_ord_tcp'
  end

  context 'windows/patchupmeterpreter/reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp',
                              'stages/windows/patchupmeterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupmeterpreter/reverse_tcp'
  end

  context 'windows/patchupmeterpreter/reverse_tcp_allports' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_allports',
                              'stages/windows/patchupmeterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupmeterpreter/reverse_tcp_allports'
  end

  context 'windows/patchupmeterpreter/reverse_tcp_dns' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_dns',
                              'stages/windows/patchupmeterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupmeterpreter/reverse_tcp_dns'
  end

  context 'windows/patchupmeterpreter/reverse_tcp_rc4' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_rc4',
                              'stages/windows/patchupmeterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupmeterpreter/reverse_tcp_rc4'
  end

  context 'windows/patchupmeterpreter/reverse_tcp_rc4_dns' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_rc4_dns',
                              'stages/windows/patchupmeterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupmeterpreter/reverse_tcp_rc4_dns'
  end

  context 'windows/shell/bind_ipv6_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/bind_ipv6_tcp',
                              'stages/windows/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell/bind_ipv6_tcp'
  end

  context 'windows/shell/bind_named_pipe' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/windows/bind_named_pipe',
                            'stages/windows/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell/bind_named_pipe'
  end

  context 'windows/shell/bind_nonx_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/bind_nonx_tcp',
                              'stages/windows/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell/bind_nonx_tcp'
  end

  context 'windows/shell/bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/bind_tcp',
                              'stages/windows/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell/bind_tcp'
  end

  context 'windows/shell/bind_tcp_rc4' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/bind_tcp_rc4',
                              'stages/windows/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell/bind_tcp_rc4'
  end

  context 'windows/shell/find_tag' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/findtag_ord',
                              'stages/windows/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell/find_tag'
  end

  context 'windows/shell/reverse_ipv6_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_ipv6_tcp',
                              'stages/windows/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell/reverse_ipv6_tcp'
  end

  context 'windows/shell/reverse_nonx_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_nonx_tcp',
                              'stages/windows/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell/reverse_nonx_tcp'
  end

  context 'windows/shell/reverse_ord_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_ord_tcp',
                              'stages/windows/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell/reverse_ord_tcp'
  end

  context 'windows/shell/reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp',
                              'stages/windows/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell/reverse_tcp'
  end

  context 'windows/shell/reverse_tcp_allports' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_allports',
                              'stages/windows/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell/reverse_tcp_allports'
  end

  context 'windows/shell/reverse_tcp_dns' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_dns',
                              'stages/windows/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell/reverse_tcp_dns'
  end

  context 'windows/shell/reverse_tcp_rc4' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_rc4',
                              'stages/windows/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell/reverse_tcp_rc4'
  end

  context 'windows/shell/reverse_tcp_rc4_dns' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_rc4_dns',
                              'stages/windows/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell/reverse_tcp_rc4_dns'
  end

  context 'windows/shell/reverse_udp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_udp',
                              'stages/windows/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell/reverse_udp'
  end

  context 'windows/shell_bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/windows/shell_bind_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell_bind_tcp'
  end

  context 'windows/shell_bind_tcp_xpfw' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/windows/shell_bind_tcp_xpfw'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell_bind_tcp_xpfw'
  end

  context 'windows/shell_hidden_bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/windows/shell_hidden_bind_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell_hidden_bind_tcp'
  end

  context 'windows/shell_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/windows/shell_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell_reverse_tcp'
  end

  context 'windows/speak_pwned' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/windows/speak_pwned'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/speak_pwned'
  end

  context 'windows/upexec/bind_ipv6_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/bind_ipv6_tcp',
                              'stages/windows/upexec'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/upexec/bind_ipv6_tcp'
  end

  context 'windows/upexec/bind_named_pipe' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/windows/bind_named_pipe',
                            'stages/windows/upexec'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/upexec/bind_named_pipe'
  end

  context 'windows/upexec/bind_nonx_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/bind_nonx_tcp',
                              'stages/windows/upexec'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/upexec/bind_nonx_tcp'
  end

  context 'windows/upexec/bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/bind_tcp',
                              'stages/windows/upexec'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/upexec/bind_tcp'
  end

  context 'windows/upexec/bind_tcp_rc4' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/bind_tcp_rc4',
                              'stages/windows/upexec'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/upexec/bind_tcp_rc4'
  end

  context 'windows/upexec/find_tag' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/findtag_ord',
                              'stages/windows/upexec'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/upexec/find_tag'
  end

  context 'windows/upexec/reverse_ipv6_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_ipv6_tcp',
                              'stages/windows/upexec'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/upexec/reverse_ipv6_tcp'
  end

  context 'windows/upexec/reverse_nonx_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_nonx_tcp',
                              'stages/windows/upexec'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/upexec/reverse_nonx_tcp'
  end

  context 'windows/upexec/reverse_ord_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_ord_tcp',
                              'stages/windows/upexec'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/upexec/reverse_ord_tcp'
  end

  context 'windows/upexec/reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp',
                              'stages/windows/upexec'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/upexec/reverse_tcp'
  end

  context 'windows/upexec/reverse_tcp_allports' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_allports',
                              'stages/windows/upexec'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/upexec/reverse_tcp_allports'
  end

  context 'windows/upexec/reverse_tcp_dns' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_dns',
                              'stages/windows/upexec'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/upexec/reverse_tcp_dns'
  end

  context 'windows/upexec/reverse_tcp_rc4' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_rc4',
                              'stages/windows/upexec'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/upexec/reverse_tcp_rc4'
  end

  context 'windows/upexec/reverse_tcp_rc4_dns' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_rc4_dns',
                              'stages/windows/upexec'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/upexec/reverse_tcp_rc4_dns'
  end

  context 'windows/upexec/reverse_udp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_udp',
                              'stages/windows/upexec'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/upexec/reverse_udp'
  end

  context 'windows/vncinject/bind_ipv6_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/bind_ipv6_tcp',
                              'stages/windows/vncinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/vncinject/bind_ipv6_tcp'
  end

  context 'windows/vncinject/bind_named_pipe' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/windows/bind_named_pipe',
                            'stages/windows/vncinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/vncinject/bind_named_pipe'
  end

  context 'windows/vncinject/bind_nonx_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/bind_nonx_tcp',
                              'stages/windows/vncinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/vncinject/bind_nonx_tcp'
  end

  context 'windows/vncinject/bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/bind_tcp',
                              'stages/windows/vncinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/vncinject/bind_tcp'
  end

  context 'windows/vncinject/bind_tcp_rc4' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/bind_tcp_rc4',
                              'stages/windows/vncinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/vncinject/bind_tcp_rc4'
  end

  context 'windows/vncinject/find_tag' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/findtag_ord',
                              'stages/windows/vncinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/vncinject/find_tag'
  end

  context 'windows/vncinject/reverse_ipv6_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_ipv6_tcp',
                              'stages/windows/vncinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/vncinject/reverse_ipv6_tcp'
  end

  context 'windows/vncinject/reverse_nonx_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_nonx_tcp',
                              'stages/windows/vncinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/vncinject/reverse_nonx_tcp'
  end

  context 'windows/vncinject/reverse_ord_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_ord_tcp',
                              'stages/windows/vncinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/vncinject/reverse_ord_tcp'
  end

  context 'windows/vncinject/reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp',
                              'stages/windows/vncinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/vncinject/reverse_tcp'
  end

  context 'windows/vncinject/reverse_tcp_allports' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_allports',
                              'stages/windows/vncinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/vncinject/reverse_tcp_allports'
  end

  context 'windows/vncinject/reverse_tcp_dns' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_dns',
                              'stages/windows/vncinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/vncinject/reverse_tcp_dns'
  end

  context 'windows/vncinject/reverse_tcp_rc4' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_rc4',
                              'stages/windows/vncinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/vncinject/reverse_tcp_rc4'
  end

  context 'windows/vncinject/reverse_tcp_rc4_dns' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_rc4_dns',
                              'stages/windows/vncinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/vncinject/reverse_tcp_rc4_dns'
  end

  context 'windows/x64/encrypted_shell/reverse_tcp' do
    it_should_behave_like 'payload is not cached',
                          ancestor_reference_names: [
                              'stagers/windows/x64/encrypted_reverse_tcp',
                              'stages/windows/x64/encrypted_shell'
                          ],
                          reference_name: 'windows/x64/encrypted_shell/reverse_tcp'
  end

  context 'windows/x64/encrypted_shell_reverse_tcp' do
    it_should_behave_like 'payload is not cached',
                          ancestor_reference_names: [
                              'singles/windows/x64/encrypted_shell_reverse_tcp'
                          ],
                          reference_name: 'windows/x64/encrypted_shell_reverse_tcp'
  end

  context 'windows/x64/exec' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/windows/x64/exec'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/exec'
  end

  context 'windows/x64/loadlibrary' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/windows/x64/loadlibrary'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/loadlibrary'
  end

  context 'windows/x64/messagebox' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/windows/x64/messagebox'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/messagebox'
  end

  context 'windows/x64/meterpreter/bind_ipv6_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/x64/bind_ipv6_tcp',
                              'stages/windows/x64/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/meterpreter/bind_ipv6_tcp'
  end

  context 'windows/x64/meterpreter/bind_ipv6_tcp_uuid' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/x64/bind_ipv6_tcp_uuid',
                              'stages/windows/x64/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/meterpreter/bind_ipv6_tcp_uuid'
  end

  context 'windows/x64/meterpreter/bind_named_pipe' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/x64/bind_named_pipe',
                              'stages/windows/x64/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/meterpreter/bind_named_pipe'
  end

  context 'windows/x64/meterpreter/bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/x64/bind_tcp',
                              'stages/windows/x64/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/meterpreter/bind_tcp'
  end

  context 'windows/x64/meterpreter/bind_tcp_rc4' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/x64/bind_tcp_rc4',
                              'stages/windows/x64/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/meterpreter/bind_tcp_rc4'
  end

  context 'windows/x64/meterpreter/bind_tcp_uuid' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/x64/bind_tcp_uuid',
                              'stages/windows/x64/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/meterpreter/bind_tcp_uuid'
  end

  context 'windows/x64/meterpreter/reverse_http' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/x64/reverse_http',
                              'stages/windows/x64/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/meterpreter/reverse_http'
  end

  context 'windows/x64/meterpreter/reverse_https' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/x64/reverse_https',
                              'stages/windows/x64/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/meterpreter/reverse_https'
  end

  context 'windows/x64/meterpreter/reverse_named_pipe' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/x64/reverse_named_pipe',
                              'stages/windows/x64/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/meterpreter/reverse_named_pipe'
  end

  context 'windows/x64/meterpreter/reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/x64/reverse_tcp',
                              'stages/windows/x64/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/meterpreter/reverse_tcp'
  end

  context 'windows/x64/meterpreter/reverse_tcp_rc4' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/x64/reverse_tcp_rc4',
                              'stages/windows/x64/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/meterpreter/reverse_tcp_rc4'
  end

  context 'windows/x64/meterpreter/reverse_tcp_uuid' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/x64/reverse_tcp_uuid',
                              'stages/windows/x64/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/meterpreter/reverse_tcp_uuid'
  end

  context 'windows/x64/meterpreter/reverse_winhttp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/x64/reverse_winhttp',
                              'stages/windows/x64/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/meterpreter/reverse_winhttp'
  end

  context 'windows/x64/meterpreter/reverse_winhttps' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/x64/reverse_winhttps',
                              'stages/windows/x64/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/meterpreter/reverse_winhttps'
  end

  context 'windows/x64/meterpreter_bind_named_pipe' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/windows/x64/meterpreter_bind_named_pipe'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/meterpreter_bind_named_pipe'
  end

  context 'windows/x64/meterpreter_bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/windows/x64/meterpreter_bind_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/meterpreter_bind_tcp'
  end

  context 'windows/x64/meterpreter_reverse_http' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/windows/x64/meterpreter_reverse_http'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/meterpreter_reverse_http'
  end

  context 'windows/x64/meterpreter_reverse_https' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/windows/x64/meterpreter_reverse_https'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/meterpreter_reverse_https'
  end

  context 'windows/x64/meterpreter_reverse_ipv6_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/windows/x64/meterpreter_reverse_ipv6_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/meterpreter_reverse_ipv6_tcp'
  end

  context 'windows/x64/meterpreter_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/windows/x64/meterpreter_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/meterpreter_reverse_tcp'
  end

  context 'windows/x64/powershell_bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/windows/x64/powershell_bind_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/powershell_bind_tcp'
  end

  context 'windows/x64/powershell_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/windows/x64/powershell_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/powershell_reverse_tcp'
  end

  context 'windows/x64/shell/bind_named_pipe' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/x64/bind_named_pipe',
                              'stages/windows/x64/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/shell/bind_named_pipe'
  end

  context 'windows/x64/shell/bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/x64/bind_tcp',
                              'stages/windows/x64/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/shell/bind_tcp'
  end

  context 'windows/x64/shell/bind_tcp_rc4' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/x64/bind_tcp_rc4',
                              'stages/windows/x64/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/shell/bind_tcp_rc4'
  end

  context 'windows/x64/shell/reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/x64/reverse_tcp',
                              'stages/windows/x64/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/shell/reverse_tcp'
  end

  context 'windows/x64/shell/reverse_tcp_rc4' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/x64/reverse_tcp_rc4',
                              'stages/windows/x64/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/shell/reverse_tcp_rc4'
  end

  context 'windows/x64/shell_bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/windows/x64/shell_bind_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/shell_bind_tcp'
  end

  context 'windows/x64/shell_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/windows/x64/shell_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/shell_reverse_tcp'
  end

  context 'windows/x64/vncinject/bind_named_pipe' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/x64/bind_named_pipe',
                              'stages/windows/x64/vncinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/vncinject/bind_named_pipe'
  end

  context 'windows/x64/vncinject/bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/x64/bind_tcp',
                              'stages/windows/x64/vncinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/vncinject/bind_tcp'
  end

  context 'windows/x64/vncinject/bind_tcp_rc4' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/x64/bind_tcp_rc4',
                              'stages/windows/x64/vncinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/vncinject/bind_tcp_rc4'
  end

  context 'windows/x64/vncinject/reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/x64/reverse_tcp',
                              'stages/windows/x64/vncinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/vncinject/reverse_tcp'
  end

  context 'windows/x64/vncinject/reverse_tcp_rc4' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'stagers/windows/x64/reverse_tcp_rc4',
                              'stages/windows/x64/vncinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/vncinject/reverse_tcp_rc4'
  end

  context 'windows/dllinject/bind_hidden_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/windows/bind_hidden_tcp',
                            'stages/windows/dllinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/dllinject/bind_hidden_tcp'
  end

  context 'windows/meterpreter/bind_hidden_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/windows/bind_hidden_tcp',
                            'stages/windows/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/bind_hidden_tcp'
  end

  context 'windows/patchupdllinject/bind_hidden_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/windows/bind_hidden_tcp',
                            'stages/windows/patchupdllinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupdllinject/bind_hidden_tcp'
  end

  context 'windows/patchupmeterpreter/bind_hidden_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/windows/bind_hidden_tcp',
                            'stages/windows/patchupmeterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupmeterpreter/bind_hidden_tcp'
  end

  context 'windows/shell/bind_hidden_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/windows/bind_hidden_tcp',
                            'stages/windows/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell/bind_hidden_tcp'
  end

  context 'windows/upexec/bind_hidden_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/windows/bind_hidden_tcp',
                            'stages/windows/upexec'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/upexec/bind_hidden_tcp'
  end

  context 'windows/vncinject/bind_hidden_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/windows/bind_hidden_tcp',
                            'stages/windows/vncinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/vncinject/bind_hidden_tcp'
  end

  context 'windows/dllinject/bind_hidden_ipknock_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/windows/bind_hidden_ipknock_tcp',
                            'stages/windows/dllinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/dllinject/bind_hidden_ipknock_tcp'
  end

  context 'windows/meterpreter/bind_hidden_ipknock_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/windows/bind_hidden_ipknock_tcp',
                            'stages/windows/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/bind_hidden_ipknock_tcp'
  end

  context 'windows/patchupdllinject/bind_hidden_ipknock_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/windows/bind_hidden_ipknock_tcp',
                            'stages/windows/patchupdllinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupdllinject/bind_hidden_ipknock_tcp'
  end

  context 'windows/patchupmeterpreter/bind_hidden_ipknock_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/windows/bind_hidden_ipknock_tcp',
                            'stages/windows/patchupmeterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupmeterpreter/bind_hidden_ipknock_tcp'
  end

  context 'windows/powershell_bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/windows/powershell_bind_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/powershell_bind_tcp'
  end

  context 'windows/powershell_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/windows/powershell_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/powershell_reverse_tcp'
  end

  context 'windows/shell/bind_hidden_ipknock_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/windows/bind_hidden_ipknock_tcp',
                            'stages/windows/shell'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell/bind_hidden_ipknock_tcp'
  end

  context 'windows/upexec/bind_hidden_ipknock_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/windows/bind_hidden_ipknock_tcp',
                            'stages/windows/upexec'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/upexec/bind_hidden_ipknock_tcp'
  end

  context 'windows/vncinject/bind_hidden_ipknock_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/windows/bind_hidden_ipknock_tcp',
                            'stages/windows/vncinject'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/vncinject/bind_hidden_ipknock_tcp'
  end

  context 'windows/meterpreter/reverse_winhttp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/windows/reverse_winhttp',
                            'stages/windows/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/reverse_winhttp'
  end

  context 'windows/meterpreter/reverse_winhttps' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/windows/reverse_winhttps',
                            'stages/windows/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/reverse_winhttps'
  end

  context 'linux/mips64/meterpreter_reverse_http' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/linux/mips64/meterpreter_reverse_http'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/mips64/meterpreter_reverse_http'
  end

  context 'linux/mips64/meterpreter_reverse_https' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/linux/mips64/meterpreter_reverse_https'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/mips64/meterpreter_reverse_https'
  end

  context 'linux/mipsbe/meterpreter_reverse_http' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/linux/mipsbe/meterpreter_reverse_http'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/mipsbe/meterpreter_reverse_http'
  end

  context 'linux/mipsbe/meterpreter_reverse_https' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/linux/mipsbe/meterpreter_reverse_https'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/mipsbe/meterpreter_reverse_https'
  end

  context 'linux/mipsle/meterpreter_reverse_http' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/linux/mipsle/meterpreter_reverse_http'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/mipsle/meterpreter_reverse_http'
  end

  context 'linux/mipsle/meterpreter_reverse_https' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/linux/mipsle/meterpreter_reverse_https'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/mipsle/meterpreter_reverse_https'
  end

  context 'linux/ppc/meterpreter_reverse_http' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/linux/ppc/meterpreter_reverse_http'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/ppc/meterpreter_reverse_http'
  end

  context 'linux/ppc/meterpreter_reverse_https' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/linux/ppc/meterpreter_reverse_https'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/ppc/meterpreter_reverse_https'
  end

  context 'linux/ppce500v2/meterpreter_reverse_http' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/ppce500v2/meterpreter_reverse_http'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/ppce500v2/meterpreter_reverse_http'
  end

  context 'linux/ppce500v2/meterpreter_reverse_https' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/ppce500v2/meterpreter_reverse_https'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/ppce500v2/meterpreter_reverse_https'
  end

  context 'linux/ppce500v2/meterpreter_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                              'singles/linux/ppce500v2/meterpreter_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/ppce500v2/meterpreter_reverse_tcp'
  end

  context 'linux/ppc64le/meterpreter_reverse_http' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/linux/ppc64le/meterpreter_reverse_http'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/ppc64le/meterpreter_reverse_http'
  end

  context 'linux/ppc64le/meterpreter_reverse_https' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/linux/ppc64le/meterpreter_reverse_https'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/ppc64le/meterpreter_reverse_https'
  end

  context 'linux/x64/meterpreter_reverse_http' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/linux/x64/meterpreter_reverse_http'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x64/meterpreter_reverse_http'
  end

  context 'linux/x64/meterpreter_reverse_https' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/linux/x64/meterpreter_reverse_https'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x64/meterpreter_reverse_https'
  end

  context 'linux/x86/meterpreter_reverse_http' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/linux/x86/meterpreter_reverse_http'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/meterpreter_reverse_http'
  end

  context 'linux/x86/meterpreter_reverse_https' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/linux/x86/meterpreter_reverse_https'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/meterpreter_reverse_https'
  end

  context 'linux/x86/metsvc_bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/linux/x86/metsvc_bind_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/metsvc_bind_tcp'
  end

  context 'linux/x86/metsvc_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/linux/x86/metsvc_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/metsvc_reverse_tcp'
  end

  context 'linux/zarch/meterpreter_reverse_http' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/linux/zarch/meterpreter_reverse_http'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/zarch/meterpreter_reverse_http'
  end

  context 'linux/zarch/meterpreter_reverse_https' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/linux/zarch/meterpreter_reverse_https'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/zarch/meterpreter_reverse_https'
  end

  context 'linux/aarch64/meterpreter/reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/linux/aarch64/reverse_tcp',
                            'stages/linux/aarch64/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/aarch64/meterpreter/reverse_tcp'
  end

  context 'linux/aarch64/meterpreter_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/linux/aarch64/meterpreter_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/aarch64/meterpreter_reverse_tcp'
  end

  context 'linux/armbe/meterpreter_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/linux/armbe/meterpreter_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/armbe/meterpreter_reverse_tcp'
  end

  context 'linux/armbe/meterpreter_reverse_http' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/linux/armbe/meterpreter_reverse_http'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/armbe/meterpreter_reverse_http'
  end

  context 'linux/armbe/meterpreter_reverse_https' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/linux/armbe/meterpreter_reverse_https'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/armbe/meterpreter_reverse_https'
  end

  context 'linux/armle/meterpreter_reverse_http' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/linux/armle/meterpreter_reverse_http'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/armle/meterpreter_reverse_http'
  end

  context 'linux/armle/meterpreter_reverse_https' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/linux/armle/meterpreter_reverse_https'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/armle/meterpreter_reverse_https'
  end

  context 'linux/armle/meterpreter/bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/linux/armle/bind_tcp',
                            'stages/linux/armle/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/armle/meterpreter/bind_tcp'
  end

  context 'linux/armle/meterpreter/reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/linux/armle/reverse_tcp',
                            'stages/linux/armle/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/armle/meterpreter/reverse_tcp'
  end

  context 'linux/armle/meterpreter_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/linux/armle/meterpreter_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/armle/meterpreter_reverse_tcp'
  end

  context 'linux/mips64/meterpreter_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/linux/mips64/meterpreter_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/mips64/meterpreter_reverse_tcp'
  end

  context 'linux/mipsbe/meterpreter/reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/linux/mipsbe/reverse_tcp',
                            'stages/linux/mipsbe/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/mipsbe/meterpreter/reverse_tcp'
  end

  context 'linux/mipsbe/meterpreter_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/linux/mipsbe/meterpreter_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/mipsbe/meterpreter_reverse_tcp'
  end

  context 'linux/mipsle/meterpreter/reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/linux/mipsle/reverse_tcp',
                            'stages/linux/mipsle/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/mipsle/meterpreter/reverse_tcp'
  end

  context 'linux/mipsle/meterpreter_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/linux/mipsle/meterpreter_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/mipsle/meterpreter_reverse_tcp'
  end

  context 'linux/ppc/meterpreter_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/linux/ppc/meterpreter_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/ppc/meterpreter_reverse_tcp'
  end

  context 'linux/ppc64le/meterpreter_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/linux/ppc64le/meterpreter_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/ppc64le/meterpreter_reverse_tcp'
  end

  context 'linux/x64/meterpreter/bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/linux/x64/bind_tcp',
                            'stages/linux/x64/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x64/meterpreter/bind_tcp'
  end

  context 'linux/x64/meterpreter/reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/linux/x64/reverse_tcp',
                            'stages/linux/x64/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x64/meterpreter/reverse_tcp'
  end

  context 'linux/x64/meterpreter_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/linux/x64/meterpreter_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x64/meterpreter_reverse_tcp'
  end

  context 'linux/x86/meterpreter/bind_ipv6_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/linux/x86/bind_ipv6_tcp',
                            'stages/linux/x86/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/meterpreter/bind_ipv6_tcp'
  end

  context 'linux/x86/meterpreter/bind_ipv6_tcp_uuid' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/linux/x86/bind_ipv6_tcp_uuid',
                            'stages/linux/x86/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/meterpreter/bind_ipv6_tcp_uuid'
  end

  context 'linux/x86/meterpreter/bind_nonx_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/linux/x86/bind_nonx_tcp',
                            'stages/linux/x86/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/meterpreter/bind_nonx_tcp'
  end

  context 'linux/x86/meterpreter/bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/linux/x86/bind_tcp',
                            'stages/linux/x86/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/meterpreter/bind_tcp'
  end

  context 'linux/x86/meterpreter/bind_tcp_uuid' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/linux/x86/bind_tcp_uuid',
                            'stages/linux/x86/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/meterpreter/bind_tcp_uuid'
  end

  context 'linux/x86/meterpreter/find_tag' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/linux/x86/find_tag',
                            'stages/linux/x86/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/meterpreter/find_tag'
  end

  context 'linux/x86/meterpreter/reverse_ipv6_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/linux/x86/reverse_ipv6_tcp',
                            'stages/linux/x86/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/meterpreter/reverse_ipv6_tcp'
  end

  context 'linux/x86/meterpreter/reverse_nonx_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/linux/x86/reverse_nonx_tcp',
                            'stages/linux/x86/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/meterpreter/reverse_nonx_tcp'
  end

  context 'linux/x86/meterpreter/reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/linux/x86/reverse_tcp',
                            'stages/linux/x86/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/meterpreter/reverse_tcp'
  end

  context 'linux/x86/meterpreter/reverse_tcp_uuid' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'stagers/linux/x86/reverse_tcp_uuid',
                            'stages/linux/x86/meterpreter'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/meterpreter/reverse_tcp_uuid'
  end

  context 'linux/x86/meterpreter_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/linux/x86/meterpreter_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/meterpreter_reverse_tcp'
  end

  context 'linux/zarch/meterpreter_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/linux/zarch/meterpreter_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/zarch/meterpreter_reverse_tcp'
  end

  context 'r/shell_bind_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/r/shell_bind_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'r/shell_bind_tcp'
  end

  context 'r/shell_reverse_tcp' do
    it_should_behave_like 'payload cached size is consistent',
                          ancestor_reference_names: [
                            'singles/r/shell_reverse_tcp'
                          ],
                          dynamic_size: false,
                          modules_pathname: modules_pathname,
                          reference_name: 'r/shell_reverse_tcp'
  end
end
