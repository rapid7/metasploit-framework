require 'spec_helper'

describe 'modules/payloads', :content do
  modules_pathname = Pathname.new(__FILE__).parent.parent.parent.join('modules')

  include_context 'untested payloads', modules_pathname: modules_pathname

  context 'aix/ppc/shell_bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/aix/ppc/shell_bind_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'aix/ppc/shell_bind_tcp'
  end

  context 'aix/ppc/shell_find_port' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/aix/ppc/shell_find_port'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'aix/ppc/shell_find_port'
  end

  context 'aix/ppc/shell_interact' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/aix/ppc/shell_interact'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'aix/ppc/shell_interact'
  end

  context 'aix/ppc/shell_reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/aix/ppc/shell_reverse_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'aix/ppc/shell_reverse_tcp'
  end

  context 'android/meterpreter/reverse_http' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/android/reverse_http',
                              'stages/android/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'android/meterpreter/reverse_http'
  end

  context 'android/meterpreter/reverse_https' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/android/reverse_https',
                              'stages/android/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'android/meterpreter/reverse_https'
  end

  context 'android/meterpreter/reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/android/reverse_tcp',
                              'stages/android/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'android/meterpreter/reverse_tcp'
  end

  context 'android/shell/reverse_http' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/android/reverse_http',
                              'stages/android/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'android/shell/reverse_http'
  end

  context 'android/shell/reverse_https' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/android/reverse_https',
                              'stages/android/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'android/shell/reverse_https'
  end

  context 'android/shell/reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/android/reverse_tcp',
                              'stages/android/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'android/shell/reverse_tcp'
  end

  context 'bsd/sparc/shell_bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/bsd/sparc/shell_bind_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/sparc/shell_bind_tcp'
  end

  context 'bsd/sparc/shell_reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/bsd/sparc/shell_reverse_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/sparc/shell_reverse_tcp'
  end

  context 'bsd/x86/exec' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/bsd/x86/exec'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/x86/exec'
  end

  context 'bsd/x86/metsvc_bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/bsd/x86/metsvc_bind_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/x86/metsvc_bind_tcp'
  end

  context 'bsd/x86/metsvc_reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/bsd/x86/metsvc_reverse_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/x86/metsvc_reverse_tcp'
  end

  context 'bsd/x86/shell/bind_ipv6_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/bsd/x86/bind_ipv6_tcp',
                              'stages/bsd/x86/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/x86/shell/bind_ipv6_tcp'
  end

  context 'bsd/x86/shell/bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/bsd/x86/bind_tcp',
                              'stages/bsd/x86/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/x86/shell/bind_tcp'
  end

  context 'bsd/x86/shell/find_tag' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/bsd/x86/find_tag',
                              'stages/bsd/x86/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/x86/shell/find_tag'
  end

  context 'bsd/x86/shell/reverse_ipv6_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/bsd/x86/reverse_ipv6_tcp',
                              'stages/bsd/x86/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/x86/shell/reverse_ipv6_tcp'
  end

  context 'bsd/x86/shell/reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/bsd/x86/reverse_tcp',
                              'stages/bsd/x86/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/x86/shell/reverse_tcp'
  end

  context 'bsd/x86/shell_bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/bsd/x86/shell_bind_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/x86/shell_bind_tcp'
  end

  context 'bsd/x86/shell_bind_tcp_ipv6' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/bsd/x86/shell_bind_tcp_ipv6'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/x86/shell_bind_tcp_ipv6'
  end

  context 'bsd/x86/shell_find_port' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/bsd/x86/shell_find_port'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/x86/shell_find_port'
  end

  context 'bsd/x86/shell_find_tag' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/bsd/x86/shell_find_tag'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/x86/shell_find_tag'
  end

  context 'bsd/x86/shell_reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/bsd/x86/shell_reverse_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/x86/shell_reverse_tcp'
  end

  context 'bsd/x86/shell_reverse_tcp_ipv6' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/bsd/x86/shell_reverse_tcp_ipv6'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'bsd/x86/shell_reverse_tcp_ipv6'
  end

  context 'bsdi/x86/shell/bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/bsdi/x86/bind_tcp',
                              'stages/bsdi/x86/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'bsdi/x86/shell/bind_tcp'
  end

  context 'bsdi/x86/shell/reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/bsdi/x86/reverse_tcp',
                              'stages/bsdi/x86/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'bsdi/x86/shell/reverse_tcp'
  end

  context 'bsdi/x86/shell_bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/bsdi/x86/shell_bind_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'bsdi/x86/shell_bind_tcp'
  end

  context 'bsdi/x86/shell_find_port' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/bsdi/x86/shell_find_port'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'bsdi/x86/shell_find_port'
  end

  context 'bsdi/x86/shell_reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/bsdi/x86/shell_reverse_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'bsdi/x86/shell_reverse_tcp'
  end

  context 'cmd/unix/bind_awk' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/unix/bind_awk'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/bind_awk'
  end

  context 'cmd/unix/bind_inetd' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/unix/bind_inetd'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/bind_inetd'
  end

  context 'cmd/unix/bind_lua' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/unix/bind_lua'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/bind_lua'
  end

  context 'cmd/unix/bind_netcat' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/unix/bind_netcat'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/bind_netcat'
  end

  context 'cmd/unix/bind_netcat_gaping' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/unix/bind_netcat_gaping'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/bind_netcat_gaping'
  end

  context 'cmd/unix/bind_netcat_gaping_ipv6' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/unix/bind_netcat_gaping_ipv6'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/bind_netcat_gaping_ipv6'
  end

  context 'cmd/unix/bind_nodejs' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/unix/bind_nodejs'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/bind_nodejs'
  end

  context 'cmd/unix/bind_perl' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/unix/bind_perl'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/bind_perl'
  end

  context 'cmd/unix/bind_perl_ipv6' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/unix/bind_perl_ipv6'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/bind_perl_ipv6'
  end

  context 'cmd/unix/bind_ruby' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/unix/bind_ruby'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/bind_ruby'
  end

  context 'cmd/unix/bind_ruby_ipv6' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/unix/bind_ruby_ipv6'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/bind_ruby_ipv6'
  end

  context 'cmd/unix/bind_zsh' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/unix/bind_zsh'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/bind_zsh'
  end

  context 'cmd/unix/generic' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/unix/generic'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/generic'
  end

  context 'cmd/unix/interact' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/unix/interact'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/interact'
  end

  context 'cmd/unix/reverse' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse'
  end

  context 'cmd/unix/reverse_awk' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse_awk'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_awk'
  end

  context 'cmd/unix/reverse_bash' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse_bash'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_bash'
  end

  context 'cmd/unix/reverse_bash_telnet_ssl' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse_bash_telnet_ssl'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_bash_telnet_ssl'
  end

  context 'cmd/unix/reverse_lua' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse_lua'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_lua'
  end

  context 'cmd/unix/reverse_netcat' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse_netcat'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_netcat'
  end

  context 'cmd/unix/reverse_netcat_gaping' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse_netcat_gaping'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_netcat_gaping'
  end

  context 'cmd/unix/reverse_nodejs' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse_nodejs'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_nodejs'
  end

  context 'cmd/unix/reverse_openssl' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse_openssl'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_openssl'
  end

  context 'cmd/unix/reverse_perl' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse_perl'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_perl'
  end

  context 'cmd/unix/reverse_perl_ssl' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse_perl_ssl'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_perl_ssl'
  end

  context 'cmd/unix/reverse_php_ssl' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse_php_ssl'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_php_ssl'
  end

  context 'cmd/unix/reverse_python' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse_python'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_python'
  end

  context 'cmd/unix/reverse_python_ssl' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse_python_ssl'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_python_ssl'
  end

  context 'cmd/unix/reverse_ruby' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse_ruby'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_ruby'
  end

  context 'cmd/unix/reverse_ruby_ssl' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse_ruby_ssl'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_ruby_ssl'
  end

  context 'cmd/unix/reverse_ssl_double_telnet' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse_ssl_double_telnet'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_ssl_double_telnet'
  end

  context 'cmd/unix/reverse_zsh' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/unix/reverse_zsh'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/unix/reverse_zsh'
  end

  context 'cmd/windows/adduser' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/windows/adduser'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/windows/adduser'
  end

  context 'cmd/windows/bind_lua' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/windows/bind_lua'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/windows/bind_lua'
  end

  context 'cmd/windows/bind_perl' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/windows/bind_perl'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/windows/bind_perl'
  end

  context 'cmd/windows/bind_perl_ipv6' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/windows/bind_perl_ipv6'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/windows/bind_perl_ipv6'
  end

  context 'cmd/windows/bind_ruby' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/windows/bind_ruby'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/windows/bind_ruby'
  end

  context 'cmd/windows/download_eval_vbs' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/windows/download_eval_vbs'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/windows/download_eval_vbs'
  end

  context 'cmd/windows/download_exec_vbs' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/windows/download_exec_vbs'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/windows/download_exec_vbs'
  end

  context 'cmd/windows/generic' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/windows/generic'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/windows/generic'
  end

  context 'cmd/windows/reverse_lua' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/windows/reverse_lua'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/windows/reverse_lua'
  end

  context 'cmd/windows/reverse_perl' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/windows/reverse_perl'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/windows/reverse_perl'
  end

  context 'cmd/windows/reverse_powershell' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/windows/reverse_powershell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/windows/reverse_powershell'
  end

  context 'cmd/windows/reverse_ruby' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/cmd/windows/reverse_ruby'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'cmd/windows/reverse_ruby'
  end

  context 'firefox/exec' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/firefox/exec'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'firefox/exec'
  end

  context 'firefox/shell_bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/firefox/shell_bind_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'firefox/shell_bind_tcp'
  end

  context 'firefox/shell_reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/firefox/shell_reverse_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'firefox/shell_reverse_tcp'
  end

  context 'generic/custom' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/generic/custom'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'generic/custom'
  end

  context 'generic/debug_trap' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/generic/debug_trap'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'generic/debug_trap'
  end

  context 'generic/shell_bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/generic/shell_bind_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'generic/shell_bind_tcp'
  end

  context 'generic/shell_reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/generic/shell_reverse_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'generic/shell_reverse_tcp'
  end

  context 'generic/tight_loop' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/generic/tight_loop'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'generic/tight_loop'
  end

  context 'java/jsp_shell_bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/java/jsp_shell_bind_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'java/jsp_shell_bind_tcp'
  end

  context 'java/jsp_shell_reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/java/jsp_shell_reverse_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'java/jsp_shell_reverse_tcp'
  end

  context 'java/meterpreter/bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/java/bind_tcp',
                              'stages/java/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'java/meterpreter/bind_tcp'
  end

  context 'java/meterpreter/reverse_http' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/java/reverse_http',
                              'stages/java/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'java/meterpreter/reverse_http'
  end

  context 'java/meterpreter/reverse_https' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/java/reverse_https',
                              'stages/java/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'java/meterpreter/reverse_https'
  end

  context 'java/meterpreter/reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/java/reverse_tcp',
                              'stages/java/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'java/meterpreter/reverse_tcp'
  end

  context 'java/shell/bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/java/bind_tcp',
                              'stages/java/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'java/shell/bind_tcp'
  end

  context 'java/shell/reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/java/reverse_tcp',
                              'stages/java/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'java/shell/reverse_tcp'
  end

  context 'java/shell_reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/java/shell_reverse_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'java/shell_reverse_tcp'
  end

  context 'linux/armle/adduser' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/linux/armle/adduser'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/armle/adduser'
  end

  context 'linux/armle/exec' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/linux/armle/exec'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/armle/exec'
  end

  context 'linux/armle/shell/bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/linux/armle/bind_tcp',
                              'stages/linux/armle/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/armle/shell/bind_tcp'
  end

  context 'linux/armle/shell/reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/linux/armle/reverse_tcp',
                              'stages/linux/armle/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/armle/shell/reverse_tcp'
  end

  context 'linux/armle/shell_bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/linux/armle/shell_bind_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/armle/shell_bind_tcp'
  end

  context 'linux/armle/shell_reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/linux/armle/shell_reverse_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/armle/shell_reverse_tcp'
  end

  context 'linux/mipsbe/exec' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/linux/mipsbe/exec'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/mipsbe/exec'
  end

  context 'linux/mipsbe/reboot' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/linux/mipsbe/reboot'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/mipsbe/reboot'
  end

  context 'linux/mipsbe/shell/reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/linux/mipsbe/reverse_tcp',
                              'stages/linux/mipsbe/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/mipsbe/shell/reverse_tcp'
  end

  context 'linux/mipsbe/shell_bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/linux/mipsbe/shell_bind_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/mipsbe/shell_bind_tcp'
  end

  context 'linux/mipsbe/shell_reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/linux/mipsbe/shell_reverse_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/mipsbe/shell_reverse_tcp'
  end

  context 'linux/mipsle/exec' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/linux/mipsle/exec'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/mipsle/exec'
  end

  context 'linux/mipsle/reboot' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/linux/mipsle/reboot'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/mipsle/reboot'
  end

  context 'linux/mipsle/shell/reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/linux/mipsle/reverse_tcp',
                              'stages/linux/mipsle/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/mipsle/shell/reverse_tcp'
  end

  context 'linux/mipsle/shell_bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/linux/mipsle/shell_bind_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/mipsle/shell_bind_tcp'
  end

  context 'linux/mipsle/shell_reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/linux/mipsle/shell_reverse_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/mipsle/shell_reverse_tcp'
  end

  context 'linux/ppc/shell_bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/linux/ppc/shell_bind_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/ppc/shell_bind_tcp'
  end

  context 'linux/ppc/shell_find_port' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/linux/ppc/shell_find_port'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/ppc/shell_find_port'
  end

  context 'linux/ppc/shell_reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/linux/ppc/shell_reverse_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/ppc/shell_reverse_tcp'
  end

  context 'linux/ppc64/shell_bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/linux/ppc64/shell_bind_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/ppc64/shell_bind_tcp'
  end

  context 'linux/ppc64/shell_find_port' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/linux/ppc64/shell_find_port'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/ppc64/shell_find_port'
  end

  context 'linux/ppc64/shell_reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/linux/ppc64/shell_reverse_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/ppc64/shell_reverse_tcp'
  end

  context 'linux/x64/exec' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/linux/x64/exec'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x64/exec'
  end

  context 'linux/x64/shell/bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/linux/x64/bind_tcp',
                              'stages/linux/x64/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x64/shell/bind_tcp'
  end

  context 'linux/x64/shell/reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/linux/x64/reverse_tcp',
                              'stages/linux/x64/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x64/shell/reverse_tcp'
  end

  context 'linux/x64/shell_bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/linux/x64/shell_bind_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x64/shell_bind_tcp'
  end

  context 'linux/x64/shell_bind_tcp_random_port' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/linux/x64/shell_bind_tcp_random_port'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x64/shell_bind_tcp_random_port'
  end

  context 'linux/x64/shell_find_port' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/linux/x64/shell_find_port'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x64/shell_find_port'
  end

  context 'linux/x64/shell_reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/linux/x64/shell_reverse_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x64/shell_reverse_tcp'
  end

  context 'linux/x86/adduser' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/linux/x86/adduser'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/adduser'
  end

  context 'linux/x86/chmod' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/linux/x86/chmod'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/chmod'
  end

  context 'linux/x86/exec' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/linux/x86/exec'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/exec'
  end

  context 'linux/x86/meterpreter/bind_ipv6_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/linux/x86/bind_ipv6_tcp',
                              'stages/linux/x86/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/meterpreter/bind_ipv6_tcp'
  end

  context 'linux/x86/meterpreter/bind_nonx_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/linux/x86/bind_nonx_tcp',
                              'stages/linux/x86/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/meterpreter/bind_nonx_tcp'
  end

  context 'linux/x86/meterpreter/bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/linux/x86/bind_tcp',
                              'stages/linux/x86/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/meterpreter/bind_tcp'
  end

  context 'linux/x86/meterpreter/find_tag' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/linux/x86/find_tag',
                              'stages/linux/x86/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/meterpreter/find_tag'
  end

  context 'linux/x86/meterpreter/reverse_ipv6_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/linux/x86/reverse_ipv6_tcp',
                              'stages/linux/x86/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/meterpreter/reverse_ipv6_tcp'
  end

  context 'linux/x86/meterpreter/reverse_nonx_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/linux/x86/reverse_nonx_tcp',
                              'stages/linux/x86/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/meterpreter/reverse_nonx_tcp'
  end

  context 'linux/x86/meterpreter/reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/linux/x86/reverse_tcp',
                              'stages/linux/x86/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/meterpreter/reverse_tcp'
  end

  context 'linux/x86/metsvc_bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/linux/x86/metsvc_bind_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/metsvc_bind_tcp'
  end

  context 'linux/x86/metsvc_reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/linux/x86/metsvc_reverse_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/metsvc_reverse_tcp'
  end

  context 'linux/x86/read_file' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/linux/x86/read_file'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/read_file'
  end

  context 'linux/x86/shell/bind_ipv6_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/linux/x86/bind_ipv6_tcp',
                              'stages/linux/x86/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/shell/bind_ipv6_tcp'
  end

  context 'linux/x86/shell/bind_nonx_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/linux/x86/bind_nonx_tcp',
                              'stages/linux/x86/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/shell/bind_nonx_tcp'
  end

  context 'linux/x86/shell/bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/linux/x86/bind_tcp',
                              'stages/linux/x86/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/shell/bind_tcp'
  end

  context 'linux/x86/shell/find_tag' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/linux/x86/find_tag',
                              'stages/linux/x86/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/shell/find_tag'
  end

  context 'linux/x86/shell/reverse_ipv6_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/linux/x86/reverse_ipv6_tcp',
                              'stages/linux/x86/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/shell/reverse_ipv6_tcp'
  end

  context 'linux/x86/shell/reverse_nonx_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/linux/x86/reverse_nonx_tcp',
                              'stages/linux/x86/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/shell/reverse_nonx_tcp'
  end

  context 'linux/x86/shell/reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/linux/x86/reverse_tcp',
                              'stages/linux/x86/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/shell/reverse_tcp'
  end

  context 'linux/x86/shell_bind_ipv6_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/linux/x86/shell_bind_ipv6_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/shell_bind_ipv6_tcp'
  end

  context 'linux/x86/shell_bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/linux/x86/shell_bind_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/shell_bind_tcp'
  end

  context 'linux/x86/shell_bind_tcp_random_port' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/linux/x86/shell_bind_tcp_random_port'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/shell_bind_tcp_random_port'
  end

  context 'linux/x86/shell_find_port' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/linux/x86/shell_find_port'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/shell_find_port'
  end

  context 'linux/x86/shell_find_tag' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/linux/x86/shell_find_tag'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/shell_find_tag'
  end

  context 'linux/x86/shell_reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/linux/x86/shell_reverse_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/shell_reverse_tcp'
  end

  context 'linux/x86/shell_reverse_tcp2' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/linux/x86/shell_reverse_tcp2'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'linux/x86/shell_reverse_tcp2'
  end

  context 'netware/shell/reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/netware/reverse_tcp',
                              'stages/netware/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'netware/shell/reverse_tcp'
  end

  context 'nodejs/shell_bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/nodejs/shell_bind_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'nodejs/shell_bind_tcp'
  end

  context 'nodejs/shell_reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/nodejs/shell_reverse_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'nodejs/shell_reverse_tcp'
  end

  context 'nodejs/shell_reverse_tcp_ssl' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/nodejs/shell_reverse_tcp_ssl'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'nodejs/shell_reverse_tcp_ssl'
  end

  context 'osx/armle/execute/bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/osx/armle/bind_tcp',
                              'stages/osx/armle/execute'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/armle/execute/bind_tcp'
  end

  context 'osx/armle/execute/reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/osx/armle/reverse_tcp',
                              'stages/osx/armle/execute'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/armle/execute/reverse_tcp'
  end

  context 'osx/armle/shell/bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/osx/armle/bind_tcp',
                              'stages/osx/armle/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/armle/shell/bind_tcp'
  end

  context 'osx/armle/shell/reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/osx/armle/reverse_tcp',
                              'stages/osx/armle/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/armle/shell/reverse_tcp'
  end

  context 'osx/armle/shell_bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/osx/armle/shell_bind_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/armle/shell_bind_tcp'
  end

  context 'osx/armle/shell_reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/osx/armle/shell_reverse_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/armle/shell_reverse_tcp'
  end

  context 'osx/armle/vibrate' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/osx/armle/vibrate'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/armle/vibrate'
  end

  context 'osx/ppc/shell/bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/osx/ppc/bind_tcp',
                              'stages/osx/ppc/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/ppc/shell/bind_tcp'
  end

  context 'osx/ppc/shell/find_tag' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/osx/ppc/find_tag',
                              'stages/osx/ppc/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/ppc/shell/find_tag'
  end

  context 'osx/ppc/shell/reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/osx/ppc/reverse_tcp',
                              'stages/osx/ppc/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/ppc/shell/reverse_tcp'
  end

  context 'osx/ppc/shell_bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/osx/ppc/shell_bind_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/ppc/shell_bind_tcp'
  end

  context 'osx/ppc/shell_reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/osx/ppc/shell_reverse_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/ppc/shell_reverse_tcp'
  end

  context 'osx/x64/dupandexecve/bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/osx/x64/bind_tcp',
                              'stages/osx/x64/dupandexecve'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x64/dupandexecve/bind_tcp'
  end

  context 'osx/x64/dupandexecve/reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/osx/x64/reverse_tcp',
                              'stages/osx/x64/dupandexecve'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x64/dupandexecve/reverse_tcp'
  end

  context 'osx/x64/exec' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/osx/x64/exec'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x64/exec'
  end

  context 'osx/x64/say' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/osx/x64/say'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x64/say'
  end

  context 'osx/x64/shell_bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/osx/x64/shell_bind_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x64/shell_bind_tcp'
  end

  context 'osx/x64/shell_find_tag' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/osx/x64/shell_find_tag'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x64/shell_find_tag'
  end

  context 'osx/x64/shell_reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/osx/x64/shell_reverse_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x64/shell_reverse_tcp'
  end

  context 'osx/x86/bundleinject/bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/osx/x86/bind_tcp',
                              'stages/osx/x86/bundleinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x86/bundleinject/bind_tcp'
  end

  context 'osx/x86/bundleinject/reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/osx/x86/reverse_tcp',
                              'stages/osx/x86/bundleinject',
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x86/bundleinject/reverse_tcp'
  end

  context 'osx/x86/exec' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/osx/x86/exec'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x86/exec'
  end

  context 'osx/x86/isight/bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/osx/x86/bind_tcp',
                              'stages/osx/x86/isight'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x86/isight/bind_tcp'
  end

  context 'osx/x86/isight/reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/osx/x86/reverse_tcp',
                              'stages/osx/x86/isight'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x86/isight/reverse_tcp'
  end

  context 'osx/x86/shell_bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/osx/x86/shell_bind_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x86/shell_bind_tcp'
  end

  context 'osx/x86/shell_find_port' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/osx/x86/shell_find_port'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x86/shell_find_port'
  end

  context 'osx/x86/shell_reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/osx/x86/shell_reverse_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x86/shell_reverse_tcp'
  end

  context 'osx/x86/vforkshell/bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/osx/x86/bind_tcp',
                              'stages/osx/x86/vforkshell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x86/vforkshell/bind_tcp'
  end

  context 'osx/x86/vforkshell/reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/osx/x86/reverse_tcp',
                              'stages/osx/x86/vforkshell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x86/vforkshell/reverse_tcp'
  end

  context 'osx/x86/vforkshell_bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/osx/x86/vforkshell_bind_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x86/vforkshell_bind_tcp'
  end

  context 'osx/x86/vforkshell_reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/osx/x86/vforkshell_reverse_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'osx/x86/vforkshell_reverse_tcp'
  end

  context 'php/bind_perl' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/php/bind_perl'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'php/bind_perl'
  end

  context 'php/bind_perl_ipv6' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/php/bind_perl_ipv6'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'php/bind_perl_ipv6'
  end

  context 'php/bind_php' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/php/bind_php'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'php/bind_php'
  end

  context 'php/bind_php_ipv6' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/php/bind_php_ipv6'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'php/bind_php_ipv6'
  end

  context 'php/download_exec' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/php/download_exec'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'php/download_exec'
  end

  context 'php/exec' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/php/exec'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'php/exec'
  end

  context 'php/meterpreter/bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/php/bind_tcp',
                              'stages/php/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'php/meterpreter/bind_tcp'
  end

  context 'php/meterpreter/bind_tcp_ipv6' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/php/bind_tcp_ipv6',
                              'stages/php/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'php/meterpreter/bind_tcp_ipv6'
  end

  context 'php/meterpreter/reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/php/reverse_tcp',
                              'stages/php/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'php/meterpreter/reverse_tcp'
  end

  context 'php/meterpreter_reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/php/meterpreter_reverse_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'php/meterpreter_reverse_tcp'
  end

  context 'php/reverse_perl' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/php/reverse_perl'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'php/reverse_perl'
  end

  context 'php/reverse_php' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/php/reverse_php'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'php/reverse_php'
  end

  context 'php/shell_findsock' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/php/shell_findsock'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'php/shell_findsock'
  end

  context 'python/meterpreter/bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/python/bind_tcp',
                              'stages/python/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'python/meterpreter/bind_tcp'
  end

  context 'python/meterpreter/reverse_http' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                            'stagers/python/reverse_http',
                            'stages/python/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'python/meterpreter/reverse_http'
  end

  context 'python/meterpreter/reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/python/reverse_tcp',
                              'stages/python/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'python/meterpreter/reverse_tcp'
  end

  context 'python/shell_reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/python/shell_reverse_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'python/shell_reverse_tcp'
  end

  context 'python/shell_reverse_tcp_ssl' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/python/shell_reverse_tcp_ssl'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'python/shell_reverse_tcp_ssl'
  end

  context 'ruby/shell_bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/ruby/shell_bind_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'ruby/shell_bind_tcp'
  end

  context 'ruby/shell_bind_tcp_ipv6' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/ruby/shell_bind_tcp_ipv6'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'ruby/shell_bind_tcp_ipv6'
  end

  context 'ruby/shell_reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/ruby/shell_reverse_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'ruby/shell_reverse_tcp'
  end

  context 'ruby/shell_reverse_tcp_ssl' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/ruby/shell_reverse_tcp_ssl'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'ruby/shell_reverse_tcp_ssl'
  end

  context 'solaris/sparc/shell_bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/solaris/sparc/shell_bind_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'solaris/sparc/shell_bind_tcp'
  end

  context 'solaris/sparc/shell_find_port' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/solaris/sparc/shell_find_port'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'solaris/sparc/shell_find_port'
  end

  context 'solaris/sparc/shell_reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/solaris/sparc/shell_reverse_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'solaris/sparc/shell_reverse_tcp'
  end

  context 'solaris/x86/shell_bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/solaris/x86/shell_bind_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'solaris/x86/shell_bind_tcp'
  end

  context 'solaris/x86/shell_find_port' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/solaris/x86/shell_find_port'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'solaris/x86/shell_find_port'
  end

  context 'solaris/x86/shell_reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/solaris/x86/shell_reverse_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'solaris/x86/shell_reverse_tcp'
  end

  context 'tty/unix/interact' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/tty/unix/interact'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'tty/unix/interact'
  end

  context 'windows/adduser' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/windows/adduser'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/adduser'
  end

  context 'windows/dllinject/bind_ipv6_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/bind_ipv6_tcp',
                              'stages/windows/dllinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/dllinject/bind_ipv6_tcp'
  end

  context 'windows/dllinject/bind_nonx_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/bind_nonx_tcp',
                              'stages/windows/dllinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/dllinject/bind_nonx_tcp'
  end

  context 'windows/dllinject/bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/bind_tcp',
                              'stages/windows/dllinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/dllinject/bind_tcp'
  end

  context 'windows/dllinject/bind_tcp_rc4' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/bind_tcp_rc4',
                              'stages/windows/dllinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/dllinject/bind_tcp_rc4'
  end

  context 'windows/dllinject/find_tag' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/findtag_ord',
                              'stages/windows/dllinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/dllinject/find_tag'
  end

  context 'windows/dllinject/reverse_hop_http' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_hop_http',
                              'stages/windows/dllinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/dllinject/reverse_hop_http'
  end

  context 'windows/dllinject/reverse_http' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_http',
                              'stages/windows/dllinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/dllinject/reverse_http'
  end

  context 'windows/dllinject/reverse_ipv6_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_ipv6_tcp',
                              'stages/windows/dllinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/dllinject/reverse_ipv6_tcp'
  end

  context 'windows/dllinject/reverse_nonx_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_nonx_tcp',
                              'stages/windows/dllinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/dllinject/reverse_nonx_tcp'
  end

  context 'windows/dllinject/reverse_ord_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_ord_tcp',
                              'stages/windows/dllinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/dllinject/reverse_ord_tcp'
  end

  context 'windows/dllinject/reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp',
                              'stages/windows/dllinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/dllinject/reverse_tcp'
  end

  context 'windows/dllinject/reverse_tcp_allports' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_allports',
                              'stages/windows/dllinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/dllinject/reverse_tcp_allports'
  end

  context 'windows/dllinject/reverse_tcp_dns' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_dns',
                              'stages/windows/dllinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/dllinject/reverse_tcp_dns'
  end

  context 'windows/dllinject/reverse_tcp_rc4' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_rc4',
                              'stages/windows/dllinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/dllinject/reverse_tcp_rc4'
  end

  context 'windows/dllinject/reverse_tcp_rc4_dns' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_rc4_dns',
                              'stages/windows/dllinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/dllinject/reverse_tcp_rc4_dns'
  end

  context 'windows/dns_txt_query_exec' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/windows/dns_txt_query_exec'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/dns_txt_query_exec'
  end

  context 'windows/download_exec' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/windows/download_exec'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/download_exec'
  end

  context 'windows/exec' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/windows/exec'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/exec'
  end

  context 'windows/format_all_drives' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/windows/format_all_drives'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/format_all_drives'
  end

  context 'windows/loadlibrary' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/windows/loadlibrary'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/loadlibrary'
  end

  context 'windows/messagebox' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/windows/messagebox'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/messagebox'
  end

  context 'windows/meterpreter/bind_ipv6_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/bind_ipv6_tcp',
                              'stages/windows/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/bind_ipv6_tcp'
  end

  context 'windows/meterpreter/bind_nonx_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/bind_nonx_tcp',
                              'stages/windows/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/bind_nonx_tcp'
  end

  context 'windows/meterpreter/bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/bind_tcp',
                              'stages/windows/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/bind_tcp'
  end

  context 'windows/meterpreter/bind_tcp_rc4' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/bind_tcp_rc4',
                              'stages/windows/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/bind_tcp_rc4'
  end

  context 'windows/meterpreter/find_tag' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/findtag_ord',
                              'stages/windows/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/find_tag'
  end

  context 'windows/meterpreter/reverse_hop_http' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_hop_http',
                              'stages/windows/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/reverse_hop_http'
  end

  context 'windows/meterpreter/reverse_http' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_http',
                              'stages/windows/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/reverse_http'
  end

  context 'windows/meterpreter/reverse_https' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_https',
                              'stages/windows/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/reverse_https'
  end

  context 'windows/meterpreter/reverse_https_proxy' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_https_proxy',
                              'stages/windows/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/reverse_https_proxy'
  end

  context 'windows/meterpreter/reverse_ipv6_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_ipv6_tcp',
                              'stages/windows/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/reverse_ipv6_tcp'
  end

  context 'windows/meterpreter/reverse_nonx_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_nonx_tcp',
                              'stages/windows/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/reverse_nonx_tcp'
  end

  context 'windows/meterpreter/reverse_ord_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_ord_tcp',
                              'stages/windows/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/reverse_ord_tcp'
  end

  context 'windows/meterpreter/reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp',
                              'stages/windows/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/reverse_tcp'
  end

  context 'windows/meterpreter/reverse_tcp_allports' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_allports',
                              'stages/windows/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/reverse_tcp_allports'
  end

  context 'windows/meterpreter/reverse_tcp_dns' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_dns',
                              'stages/windows/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/reverse_tcp_dns'
  end

  context 'windows/meterpreter/reverse_tcp_rc4' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_rc4',
                              'stages/windows/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/reverse_tcp_rc4'
  end

  context 'windows/meterpreter/reverse_tcp_rc4_dns' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_rc4_dns',
                              'stages/windows/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/meterpreter/reverse_tcp_rc4_dns'
  end

  context 'windows/metsvc_bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/windows/metsvc_bind_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/metsvc_bind_tcp'
  end

  context 'windows/metsvc_reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/windows/metsvc_reverse_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/metsvc_reverse_tcp'
  end

  context 'windows/patchupdllinject/bind_ipv6_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/bind_ipv6_tcp',
                              'stages/windows/patchupdllinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupdllinject/bind_ipv6_tcp'
  end

  context 'windows/patchupdllinject/bind_nonx_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/bind_nonx_tcp',
                              'stages/windows/patchupdllinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupdllinject/bind_nonx_tcp'
  end

  context 'windows/patchupdllinject/bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/bind_tcp',
                              'stages/windows/patchupdllinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupdllinject/bind_tcp'
  end

  context 'windows/patchupdllinject/bind_tcp_rc4' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/bind_tcp_rc4',
                              'stages/windows/patchupdllinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupdllinject/bind_tcp_rc4'
  end

  context 'windows/patchupdllinject/find_tag' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/findtag_ord',
                              'stages/windows/patchupdllinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupdllinject/find_tag'
  end

  context 'windows/patchupdllinject/reverse_ipv6_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_ipv6_tcp',
                              'stages/windows/patchupdllinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupdllinject/reverse_ipv6_tcp'
  end

  context 'windows/patchupdllinject/reverse_nonx_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_nonx_tcp',
                              'stages/windows/patchupdllinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupdllinject/reverse_nonx_tcp'
  end

  context 'windows/patchupdllinject/reverse_ord_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_ord_tcp',
                              'stages/windows/patchupdllinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupdllinject/reverse_ord_tcp'
  end

  context 'windows/patchupdllinject/reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp',
                              'stages/windows/patchupdllinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupdllinject/reverse_tcp'
  end

  context 'windows/patchupdllinject/reverse_tcp_allports' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_allports',
                              'stages/windows/patchupdllinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupdllinject/reverse_tcp_allports'
  end

  context 'windows/patchupdllinject/reverse_tcp_dns' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_dns',
                              'stages/windows/patchupdllinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupdllinject/reverse_tcp_dns'
  end

  context 'windows/patchupdllinject/reverse_tcp_rc4' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_rc4',
                              'stages/windows/patchupdllinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupdllinject/reverse_tcp_rc4'
  end

  context 'windows/patchupdllinject/reverse_tcp_rc4_dns' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_rc4_dns',
                              'stages/windows/patchupdllinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupdllinject/reverse_tcp_rc4_dns'
  end

  context 'windows/patchupmeterpreter/bind_ipv6_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/bind_ipv6_tcp',
                              'stages/windows/patchupmeterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupmeterpreter/bind_ipv6_tcp'
  end

  context 'windows/patchupmeterpreter/bind_nonx_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/bind_nonx_tcp',
                              'stages/windows/patchupmeterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupmeterpreter/bind_nonx_tcp'
  end

  context 'windows/patchupmeterpreter/bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/bind_tcp',
                              'stages/windows/patchupmeterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupmeterpreter/bind_tcp'
  end

  context 'windows/patchupmeterpreter/bind_tcp_rc4' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/bind_tcp_rc4',
                              'stages/windows/patchupmeterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupmeterpreter/bind_tcp_rc4'
  end

  context 'windows/patchupmeterpreter/find_tag' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/findtag_ord',
                              'stages/windows/patchupmeterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupmeterpreter/find_tag'
  end

  context 'windows/patchupmeterpreter/reverse_ipv6_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_ipv6_tcp',
                              'stages/windows/patchupmeterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupmeterpreter/reverse_ipv6_tcp'
  end

  context 'windows/patchupmeterpreter/reverse_nonx_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_nonx_tcp',
                              'stages/windows/patchupmeterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupmeterpreter/reverse_nonx_tcp'
  end

  context 'windows/patchupmeterpreter/reverse_ord_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_ord_tcp',
                              'stages/windows/patchupmeterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupmeterpreter/reverse_ord_tcp'
  end

  context 'windows/patchupmeterpreter/reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp',
                              'stages/windows/patchupmeterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupmeterpreter/reverse_tcp'
  end

  context 'windows/patchupmeterpreter/reverse_tcp_allports' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_allports',
                              'stages/windows/patchupmeterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupmeterpreter/reverse_tcp_allports'
  end

  context 'windows/patchupmeterpreter/reverse_tcp_dns' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_dns',
                              'stages/windows/patchupmeterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupmeterpreter/reverse_tcp_dns'
  end

  context 'windows/patchupmeterpreter/reverse_tcp_rc4' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_rc4',
                              'stages/windows/patchupmeterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupmeterpreter/reverse_tcp_rc4'
  end

  context 'windows/patchupmeterpreter/reverse_tcp_rc4_dns' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_rc4_dns',
                              'stages/windows/patchupmeterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/patchupmeterpreter/reverse_tcp_rc4_dns'
  end

  context 'windows/shell/bind_ipv6_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/bind_ipv6_tcp',
                              'stages/windows/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell/bind_ipv6_tcp'
  end

  context 'windows/shell/bind_nonx_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/bind_nonx_tcp',
                              'stages/windows/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell/bind_nonx_tcp'
  end

  context 'windows/shell/bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/bind_tcp',
                              'stages/windows/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell/bind_tcp'
  end

  context 'windows/shell/bind_tcp_rc4' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/bind_tcp_rc4',
                              'stages/windows/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell/bind_tcp_rc4'
  end

  context 'windows/shell/find_tag' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/findtag_ord',
                              'stages/windows/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell/find_tag'
  end

  context 'windows/shell/reverse_hop_http' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_hop_http',
                              'stages/windows/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell/reverse_hop_http'
  end

  context 'windows/shell/reverse_http' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_http',
                              'stages/windows/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell/reverse_http'
  end

  context 'windows/shell/reverse_ipv6_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_ipv6_tcp',
                              'stages/windows/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell/reverse_ipv6_tcp'
  end

  context 'windows/shell/reverse_nonx_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_nonx_tcp',
                              'stages/windows/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell/reverse_nonx_tcp'
  end

  context 'windows/shell/reverse_ord_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_ord_tcp',
                              'stages/windows/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell/reverse_ord_tcp'
  end

  context 'windows/shell/reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp',
                              'stages/windows/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell/reverse_tcp'
  end

  context 'windows/shell/reverse_tcp_allports' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_allports',
                              'stages/windows/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell/reverse_tcp_allports'
  end

  context 'windows/shell/reverse_tcp_dns' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_dns',
                              'stages/windows/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell/reverse_tcp_dns'
  end

  context 'windows/shell/reverse_tcp_rc4' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_rc4',
                              'stages/windows/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell/reverse_tcp_rc4'
  end

  context 'windows/shell/reverse_tcp_rc4_dns' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_rc4_dns',
                              'stages/windows/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell/reverse_tcp_rc4_dns'
  end

  context 'windows/shell_bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/windows/shell_bind_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell_bind_tcp'
  end

  context 'windows/shell_bind_tcp_xpfw' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/windows/shell_bind_tcp_xpfw'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell_bind_tcp_xpfw'
  end

  context 'windows/shell_hidden_bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/windows/shell_hidden_bind_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell_hidden_bind_tcp'
  end

  context 'windows/shell_reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/windows/shell_reverse_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/shell_reverse_tcp'
  end

  context 'windows/speak_pwned' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/windows/speak_pwned'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/speak_pwned'
  end

  context 'windows/upexec/bind_ipv6_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/bind_ipv6_tcp',
                              'stages/windows/upexec'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/upexec/bind_ipv6_tcp'
  end

  context 'windows/upexec/bind_nonx_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/bind_nonx_tcp',
                              'stages/windows/upexec'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/upexec/bind_nonx_tcp'
  end

  context 'windows/upexec/bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/bind_tcp',
                              'stages/windows/upexec'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/upexec/bind_tcp'
  end

  context 'windows/upexec/bind_tcp_rc4' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/bind_tcp_rc4',
                              'stages/windows/upexec'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/upexec/bind_tcp_rc4'
  end

  context 'windows/upexec/find_tag' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/findtag_ord',
                              'stages/windows/upexec'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/upexec/find_tag'
  end

  context 'windows/upexec/reverse_hop_http' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_hop_http',
                              'stages/windows/upexec'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/upexec/reverse_hop_http'
  end

  context 'windows/upexec/reverse_http' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_http',
                              'stages/windows/upexec'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/upexec/reverse_http'
  end

  context 'windows/upexec/reverse_ipv6_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_ipv6_tcp',
                              'stages/windows/upexec'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/upexec/reverse_ipv6_tcp'
  end

  context 'windows/upexec/reverse_nonx_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_nonx_tcp',
                              'stages/windows/upexec'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/upexec/reverse_nonx_tcp'
  end

  context 'windows/upexec/reverse_ord_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_ord_tcp',
                              'stages/windows/upexec'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/upexec/reverse_ord_tcp'
  end

  context 'windows/upexec/reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp',
                              'stages/windows/upexec'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/upexec/reverse_tcp'
  end

  context 'windows/upexec/reverse_tcp_allports' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_allports',
                              'stages/windows/upexec'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/upexec/reverse_tcp_allports'
  end

  context 'windows/upexec/reverse_tcp_dns' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_dns',
                              'stages/windows/upexec'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/upexec/reverse_tcp_dns'
  end

  context 'windows/upexec/reverse_tcp_rc4' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_rc4',
                              'stages/windows/upexec'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/upexec/reverse_tcp_rc4'
  end

  context 'windows/upexec/reverse_tcp_rc4_dns' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_rc4_dns',
                              'stages/windows/upexec'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/upexec/reverse_tcp_rc4_dns'
  end

  context 'windows/vncinject/bind_ipv6_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/bind_ipv6_tcp',
                              'stages/windows/vncinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/vncinject/bind_ipv6_tcp'
  end

  context 'windows/vncinject/bind_nonx_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/bind_nonx_tcp',
                              'stages/windows/vncinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/vncinject/bind_nonx_tcp'
  end

  context 'windows/vncinject/bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/bind_tcp',
                              'stages/windows/vncinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/vncinject/bind_tcp'
  end

  context 'windows/vncinject/bind_tcp_rc4' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/bind_tcp_rc4',
                              'stages/windows/vncinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/vncinject/bind_tcp_rc4'
  end

  context 'windows/vncinject/find_tag' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/findtag_ord',
                              'stages/windows/vncinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/vncinject/find_tag'
  end

  context 'windows/vncinject/reverse_hop_http' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_hop_http',
                              'stages/windows/vncinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/vncinject/reverse_hop_http'
  end

  context 'windows/vncinject/reverse_http' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_http',
                              'stages/windows/vncinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/vncinject/reverse_http'
  end

  context 'windows/vncinject/reverse_ipv6_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_ipv6_tcp',
                              'stages/windows/vncinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/vncinject/reverse_ipv6_tcp'
  end

  context 'windows/vncinject/reverse_nonx_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_nonx_tcp',
                              'stages/windows/vncinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/vncinject/reverse_nonx_tcp'
  end

  context 'windows/vncinject/reverse_ord_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_ord_tcp',
                              'stages/windows/vncinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/vncinject/reverse_ord_tcp'
  end

  context 'windows/vncinject/reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp',
                              'stages/windows/vncinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/vncinject/reverse_tcp'
  end

  context 'windows/vncinject/reverse_tcp_allports' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_allports',
                              'stages/windows/vncinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/vncinject/reverse_tcp_allports'
  end

  context 'windows/vncinject/reverse_tcp_dns' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_dns',
                              'stages/windows/vncinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/vncinject/reverse_tcp_dns'
  end

  context 'windows/vncinject/reverse_tcp_rc4' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_rc4',
                              'stages/windows/vncinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/vncinject/reverse_tcp_rc4'
  end

  context 'windows/vncinject/reverse_tcp_rc4_dns' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/reverse_tcp_rc4_dns',
                              'stages/windows/vncinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/vncinject/reverse_tcp_rc4_dns'
  end

  context 'windows/x64/exec' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/windows/x64/exec'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/exec'
  end

  context 'windows/x64/loadlibrary' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/windows/x64/loadlibrary'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/loadlibrary'
  end

  context 'windows/x64/meterpreter/bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/x64/bind_tcp',
                              'stages/windows/x64/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/meterpreter/bind_tcp'
  end

  context 'windows/x64/meterpreter/reverse_https' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/x64/reverse_https',
                              'stages/windows/x64/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/meterpreter/reverse_https'
  end

  context 'windows/x64/meterpreter/reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/x64/reverse_tcp',
                              'stages/windows/x64/meterpreter'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/meterpreter/reverse_tcp'
  end

  context 'windows/x64/shell/bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/x64/bind_tcp',
                              'stages/windows/x64/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/shell/bind_tcp'
  end

  context 'windows/x64/shell/reverse_https' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/x64/reverse_https',
                              'stages/windows/x64/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/shell/reverse_https'
  end

  context 'windows/x64/shell/reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/x64/reverse_tcp',
                              'stages/windows/x64/shell'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/shell/reverse_tcp'
  end

  context 'windows/x64/shell_bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/windows/x64/shell_bind_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/shell_bind_tcp'
  end

  context 'windows/x64/shell_reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'singles/windows/x64/shell_reverse_tcp'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/shell_reverse_tcp'
  end

  context 'windows/x64/vncinject/bind_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/x64/bind_tcp',
                              'stages/windows/x64/vncinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/vncinject/bind_tcp'
  end

  context 'windows/x64/vncinject/reverse_https' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/x64/reverse_https',
                              'stages/windows/x64/vncinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/vncinject/reverse_https'
  end

  context 'windows/x64/vncinject/reverse_tcp' do
    it_should_behave_like 'payload can be instantiated',
                          ancestor_reference_names: [
                              'stagers/windows/x64/reverse_tcp',
                              'stages/windows/x64/vncinject'
                          ],
                          modules_pathname: modules_pathname,
                          reference_name: 'windows/x64/vncinject/reverse_tcp'
  end
end
