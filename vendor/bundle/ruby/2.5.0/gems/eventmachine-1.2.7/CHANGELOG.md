# Changelog

## 1.2.7 (May 12, 2018)
* Fix segfault on large numbers of connections [#843]

## 1.2.6 (April 30, 2018)
* *Fix segfault when an Exception is raised from unbind callback (for real this time!)*
* Fix race condition while initializing the machine [#756]
* Fix for newer compilers where bind() and std::bind() conflict [#830, #831]
* Be verbose about SSL connection errors [#807]
* Avoid explicitly calling class methods when in class scope
* Java: Add EM_PROTO_SSL/TLS definitions [#773, #791]
* Java: return zero when sending data to a closed connection [#475, #804]
* Pure Ruby: Connection::error? calls report_connection_error_status [#801]

## 1.2.5 (July 27, 2017)
* Java: Use long for larger values in oneshot timer intervals [#784, #794]

## 1.2.4 (July 27, 2017)
* Java: Add EM_PROTO_SSL/TLS definitions [#773, #791]
* Fix IPv6 UDP get_peername [#788]
* Allow for larger values in oneshot timer intervals [#784, #793]
* Update extconf.rb to allow MinGW builds with OpenSSL 1.1.0 [#785]

## 1.2.3 (February 22, 2017)
* Pure Ruby: Add get_sockname [#308, #772]
* Fix segfault when an Exception is raised from unbind callback [#765, #766]
* Allow destructors to throw when compiling in >= C++11 [#767]

## 1.2.2 (January 23, 2017)
* Java: Fix Fixnum deprecated warning in Ruby 2.4+ [#759]
* Fix uncaught C++ exception in file watcher and raise InvalidSignature [#512, #757]
* Fix connection count off-by-one for epoll and kqueue [#750]
* Fix uninitialized variable warning in EM::P::HttpClient [#749]
* Fix missing initial value for EventableDescriptor NextHeartbeat [#748]
* Fix hostname resolution on Solaris, Ilumos, SmartOS, et al [#745, #746]
* Improve reliability of tests, reduce public Internet accesses in tests [#656, #666, #749]

## 1.2.1 (November 15, 2016)
* Throw strerror(errno) when getsockname or getpeername fail [#683]
* Use a single concrete implementation of getpeername/getsockname, the rest pure virtuals [#683]
* Use gai_strerror to get the failure string from getaddrinfo [#744]
* Fix deregistering descriptor when using KQUEUE [#728]
* Fix to enable to work an example code in EM::Pool [#731]
* LineText2: Add regular expression delimiter support [#706]
* Pure Ruby: EM rescue ECONNREFUSED on initial TCP connect [#741]
* Pure Ruby: EM SSL (working start_tls) [#712]
* Pure Ruby: EM fixes [#707]
* Java: Use Acceptors to get peer and sock names if not present in Connections [#743]

## 1.2.0.1 (March 15, 2016)
* Fix crash when accepting IPv6 connections due to struct sockaddr_in [#698, #699]

## 1.2.0 (March 15, 2016)
* Integrate work from the EventMachine-LE 1.1.x versions [#570]
* Add start_tls options :ecdh_curve, :dhparam, :fail_if_no_peer_cert [#195, #275, #399, #665]
* Add start_tls option :ssl_version for choosing SSL/TLS versions and ciphers [#359, #348, #603, #654]
* Add start_tls option :sni_hostname to be passed to TLS params [#593]
* Add method EM::Channel#num_subscribers to get the number of subscribers to a channel [#640]
* Add support for proc-sources in EM::Iterator [#639]
* Factor out method cleanup_machine to cleanup code from EM.run [#650]
* Replace Exception class with StandardError [#637]
* Close socket on close_connection even after close_connection_after_writing [#694]
* Allow reusing of datagram socket/setting bind device [#662]
* Handle deferred exceptions in reactor thread [#486]
* Reimplement Queue to avoid shift/push performance problem [#311]
* Windows: Switch from gethostbyname to getaddrinfo, support IPv6 addresses [#303, #630]
* Windows: Use rake-compiler-dock to cross-compile gems [#627]
* Windows: Add AppVeyor configuration for Windows CI testing [#578]
* Windows: Bump rake-compiler to version 0.9.x [#542]
* Fix compilation on AIX (w/ XLC) [#693]
* Fix build on OpenBSD [#690]
* Fix OpenSSL compile issue on AIX 7.1 [#678]
* Fix EventMachine.fork_reactor keeps the threadpool of the original process [#425]
* Fix to prevent event machine from stopping when a raise is done in an unbind [#327]

## 1.0.9.1 (January 14, 2016)
* Fix EPROTO not defined on Windows [#676]
* Fix missing cast to struct sockaddr * [#671]
* Fix bug in OpenSSL path detection [#675]

## 1.0.9 (January 13, 2016)
* Try more ways to detect OpenSSL [#602, #643, #661, #663, #668, #669]
* Use WSAGetLastError in pipe.cpp same as ed.cpp [#659]
* Test compiler flags with the C++ compiler and add them to CXXFLAGS [#634, #651]
* Restore silent-fail on unsupported EM.epoll and EM.kqueue [#638, #649]
* getDescriptorByFileno deprecated in JRuby 1.7.x, removed in JRuby 9000 [#642, #648]
* Add -Wno-address always-true because on Windows rb_fd_select [#578]
* Remove the WITHOUT_SSL constant [#578]
* Fix SSL error when the server replies a TLS Alert to our ClientHello [#544, #653]
* Use WSAStringToAddress in lieu of inet_pton for IPv6 address detection on Windows [#595, #632]
* Fix nasty TCP/IPv6 bug [#595, #632]
* Use select_large_fdset on Solaris [#611, #625]
* Detect the Solaris Studio compiler [#611, #625]
* Throw a message with strerror included [#136, #621]

## 1.0.8 (August 6, 2015)
* fix kqueue assertion failed, postpone ArmKqueueWriter until all events are processed [#51, #176, #372, #401, #619]
* fix Rubinius GC, crank the machine from Ruby space when running Rubinius [#201, #202, #617]
* test to show that LineText2 preserves whitespace and newlines [#32, #622]
* bump up compiler warnings and resolve them [#616]
* fix Windows x64 use uintptr_t instead of unsigned long for binding pointers [#612, #615]
* fix linetext2 unroll tail recursion to avoid stack level too deep [#609]
* fix for compilation with SSL on windows [#601]
* open file descriptors and sockets with O_CLOEXEC where possible [#298, #488, #591]
* fix SmtpClient: send second EHLO after STARTTLS. [#589]
* fix nul-terminated strings in C, use StringValueCStr instead of StringValuePtr

## 1.0.7 (February 10, 2015)
* fix delay in kqueue/epoll reactor shutdown when timers exist [#587]
* fix memory leak introduced in v1.0.5 [#586]
* expose EM.set_simultaneous_accept_count [#420]
* fix busy loop when EM.run and EM.next_tick are invoked from exception handler [#452]

## 1.0.6 (February 3, 2015)
* add support for Rubinius Process::Status [#568]
* small bugfixes for SmtpServer [#449]
* update buftok.rb [#547]
* fix assertion on Write() [#525]
* work around mkmf.rb bug preventing gem installation [#574]
* add pause/resume support to jruby reactor [#556]
* fix pure ruby reactor to use 127.0.0.1 instead of localhost [#439]
* fix compilation under macruby [#243]
* add chunked encoding to http client [#111]
* fix errors on win32 when dealing with pipes [1ea45498] [#105]

## 1.0.5 (February 2, 2015)
* use monotonic clocks on Linux, OS X, Solaris, and Windows [#563]
* use the rb_fd_* API to get autosized fd_sets [#502]
* add basic tests that the DNS resolver isn't leaking timers [#571]
* update to test-unit 2.x and improve various unit tests [#551]
* remove EventMachine_t::Popen code marked by ifdef OBSOLETE [#551]
* ruby 2.0 may fail at Queue.pop, so rescue and complain to $stderr [#551]
* set file handle to INVALID_HANDLE_VALUE after closing the file [#565]
* use `defined?` instead of rescuing NameError for flow control [#535]
* fix closing files and sockets on Windows [#564]
* fix file uploads in Windows [#562]
* catch failure to fork [#539]
* use chunks for SSL write [#545]

## 1.0.4 (December 19, 2014)
* add starttls_options to smtp server [#552]
* fix closesocket on windows [#497]
* fix build on ruby 2.2 [#503]
* fix build error on ruby 1.9 [#508]
* fix timer leak during dns resolution [#489]
* add concurrency validation to EM::Iterator [#468]
* add get_file_descriptor to get fd for a signature [#467]
* add EM.attach_server and EM.attach_socket_server [#465, #466]
* calling pause from receive_data takes effect immediately [#464]
* reactor_running? returns false after fork [#455]
* fix infinite loop on double close [edc4d0e6, #441, #445]
* fix compilation issue on llvm [#433]
* fix socket error codes on win32 [ff811a81]
* fix EM.stop latency when timers exist [8b613d05, #426]
* fix infinite loop when system time changes [1427a2c80, #428]
* fix crash when callin attach/detach in the same tick [#427]
* fix compilation issue on solaris [#416]

## 1.0.3 (March 8, 2013)
* EM.system was broken in 1.0.2 release [#413]

## 1.0.2 (March 8, 2013)
* binary win32 gems now include fastfilereader shim [#222]
* fix long-standing connection timeout issues [27fdd5b, igrigorik/em-http-request#222]
* http and line protocol cleanups [#193, #151]
* reactor return value cleanup [#225]
* fix double require from gemspec [#284]
* fix smtp server reset behavior [#351]
* fix EM.system argument handling [#322]
* ruby 1.9 compat in smtp server and stomp protocols [#349, #315]
* fix pause from post_init [#380]

## 1.0.1 (February 27, 2013)
* use rb_wait_for_single_fd() on ruby 2.0 to fix rb_thread_select() deprecation [#363]
* fix epoll/kqueue mode in ruby 2.0 by removing calls to rb_enable_interrupt() [#248, #389]
* fix memory leak when verifying ssl cerificates [#403]
* fix initial connection delay [#393, #374]
* fix build on windows [#371]
