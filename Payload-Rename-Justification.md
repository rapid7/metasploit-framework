### The Issue
Many payloads perform the same task, yet have different names. This results in confusion and a bad new-user experience. Specifically, `ARCH_CMD` payloads differ greatly from their shellcode-derived brethren. For example, the most heavily used payload is `windows/meterpreter/reverse_tcp`; the equivalent in `ARCH_CMD` land is `cmd/unix/reverse`, which gives no indication that the session type will be a shell.

### The Proposal
I propose we rename all the aberrantly-named payloads to match the convention. Specifically:

* `cmd/unix/bind_awk`                        ->   `cmd/unix/shell_bind_tcp_awk`
* `cmd/unix/bind_lua`                        ->   `cmd/unix/shell_bind_tcp_lua`
* `cmd/unix/bind_netcat`                     ->   `cmd/unix/shell_bind_tcp_netcat`
* `cmd/unix/bind_netcat_gaping`              ->   `cmd/unix/shell_bind_tcp_netcat_gaping`
* `cmd/unix/bind_netcat_gaping_ipv6`         ->   `cmd/unix/shell_bind_tcp_netcat_gaping_ipv6`
* `cmd/unix/bind_nodejs`                     ->   `cmd/unix/shell_bind_tcp_nodejs`
* `cmd/unix/bind_perl`                       ->   `cmd/unix/shell_bind_tcp_perl`
* `cmd/unix/bind_perl_ipv6`                  ->   `cmd/unix/shell_bind_tcp_perl_ipv6`
* `cmd/unix/bind_ruby`                       ->   `cmd/unix/shell_bind_tcp_ruby`
* `cmd/unix/bind_ruby_ipv6`                  ->   `cmd/unix/shell_bind_tcp_ruby_ipv6`
* `cmd/unix/bind_zsh`                        ->   `cmd/unix/shell_bind_tcp_zsh`
* `cmd/unix/generic`                         ->   `cmd/unix/exec`
* `cmd/unix/reverse`                         ->   `cmd/unix/shell_reverse_tcp_telnet`
* `cmd/unix/reverse_awk`                     ->   `cmd/unix/shell_reverse_tcp_awk`
* `cmd/unix/reverse_bash`                    ->   `cmd/unix/shell_reverse_tcp_bash`
* `cmd/unix/reverse_bash_telnet_ssl`         ->   `cmd/unix/shell_reverse_tcp_bash_telnet_ssl`
* `cmd/unix/reverse_lua`                     ->   `cmd/unix/shell_reverse_tcp_lua`
* `cmd/unix/reverse_netcat`                  ->   `cmd/unix/shell_reverse_tcp_netcat`
* `cmd/unix/reverse_netcat_gaping`           ->   `cmd/unix/shell_reverse_tcp_netcat_gaping`
* `cmd/unix/reverse_nodejs`                  ->   `cmd/unix/shell_reverse_tcp_nodejs`
* `cmd/unix/reverse_openssl`                 ->   `cmd/unix/shell_reverse_tcp_openssl`
* `cmd/unix/reverse_perl`                    ->   `cmd/unix/shell_reverse_tcp_perl`
* `cmd/unix/reverse_perl_ssl`                ->   `cmd/unix/shell_reverse_tcp_perl_ssl`
* `cmd/unix/reverse_php_ssl`                 ->   `cmd/unix/shell_reverse_tcp_php_ssl`
* `cmd/unix/reverse_python`                  ->   `cmd/unix/shell_reverse_tcp_python`
* `cmd/unix/reverse_python_ssl`              ->   `cmd/unix/shell_reverse_tcp_python_ssl`
* `cmd/unix/reverse_ruby`                    ->   `cmd/unix/shell_reverse_tcp_ruby`
* `cmd/unix/reverse_ruby_ssl`                ->   `cmd/unix/shell_reverse_tcp_ruby_ssl`
* `cmd/unix/reverse_ssl_double_telnet`       ->   `cmd/unix/shell_reverse_tcp_ssl_double_telnet`
* `cmd/unix/reverse_zsh`                     ->   `cmd/unix/shell_reverse_tcp_zsh`
* `cmd/windows/bind_lua`                     ->   `cmd/windows/shell_bind_tcp_lua`
* `cmd/windows/bind_perl`                    ->   `cmd/windows/shell_bind_tcp_perl`
* `cmd/windows/bind_perl_ipv6`               ->   `cmd/windows/shell_bind_tcp_perl_ipv6`
* `cmd/windows/bind_ruby`                    ->   `cmd/windows/shell_bind_tcp_ruby`
* `cmd/windows/download_eval_vbs`            ->   `cmd/windows/download_eval_vbs`
* `cmd/windows/download_exec_vbs`            ->   `cmd/windows/download_exec_vbs`
* `cmd/windows/generic`                      ->   `cmd/windows/exec`
* `cmd/windows/reverse_lua`                  ->   `cmd/windows/shell_reverse_tcp_lua`
* `cmd/windows/reverse_perl`                 ->   `cmd/windows/shell_reverse_tcp_perl`
* `cmd/windows/reverse_ruby`                 ->   `cmd/windows/shell_reverse_tcp_ruby`


