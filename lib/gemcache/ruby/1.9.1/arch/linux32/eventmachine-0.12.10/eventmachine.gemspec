# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{eventmachine}
  s.version = "0.12.10"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = ["Francis Cianfrocca"]
  s.date = %q{2009-10-24}
  s.description = %q{EventMachine implements a fast, single-threaded engine for arbitrary network
communications. It's extremely easy to use in Ruby. EventMachine wraps all
interactions with IP sockets, allowing programs to concentrate on the
implementation of network protocols. It can be used to create both network
servers and clients. To create a server or client, a Ruby program only needs
to specify the IP address and port, and provide a Module that implements the
communications protocol. Implementations of several standard network protocols
are provided with the package, primarily to serve as examples. The real goal
of EventMachine is to enable programs to easily interface with other programs
using TCP/IP, especially if custom protocols are required.
}
  s.email = %q{garbagecat10@gmail.com}
  s.extensions = ["ext/extconf.rb", "ext/fastfilereader/extconf.rb"]
  s.files = [".gitignore", "README", "Rakefile", "docs/COPYING", "docs/ChangeLog", "docs/DEFERRABLES", "docs/EPOLL", "docs/GNU", "docs/INSTALL", "docs/KEYBOARD", "docs/LEGAL", "docs/LIGHTWEIGHT_CONCURRENCY", "docs/PURE_RUBY", "docs/RELEASE_NOTES", "docs/SMTP", "docs/SPAWNED_PROCESSES", "docs/TODO", "eventmachine.gemspec", "examples/ex_channel.rb", "examples/ex_queue.rb", "examples/helper.rb", "ext/binder.cpp", "ext/binder.h", "ext/cmain.cpp", "ext/cplusplus.cpp", "ext/ed.cpp", "ext/ed.h", "ext/em.cpp", "ext/em.h", "ext/emwin.cpp", "ext/emwin.h", "ext/epoll.cpp", "ext/epoll.h", "ext/eventmachine.h", "ext/eventmachine_cpp.h", "ext/extconf.rb", "ext/fastfilereader/extconf.rb", "ext/fastfilereader/mapper.cpp", "ext/fastfilereader/mapper.h", "ext/fastfilereader/rubymain.cpp", "ext/files.cpp", "ext/files.h", "ext/kb.cpp", "ext/page.cpp", "ext/page.h", "ext/pipe.cpp", "ext/project.h", "ext/rubymain.cpp", "ext/sigs.cpp", "ext/sigs.h", "ext/ssl.cpp", "ext/ssl.h", "java/.classpath", "java/.project", "java/src/com/rubyeventmachine/EmReactor.java", "java/src/com/rubyeventmachine/EmReactorException.java", "java/src/com/rubyeventmachine/EventableChannel.java", "java/src/com/rubyeventmachine/EventableDatagramChannel.java", "java/src/com/rubyeventmachine/EventableSocketChannel.java", "java/src/com/rubyeventmachine/application/Application.java", "java/src/com/rubyeventmachine/application/Connection.java", "java/src/com/rubyeventmachine/application/ConnectionFactory.java", "java/src/com/rubyeventmachine/application/DefaultConnectionFactory.java", "java/src/com/rubyeventmachine/application/PeriodicTimer.java", "java/src/com/rubyeventmachine/application/Timer.java", "java/src/com/rubyeventmachine/tests/ApplicationTest.java", "java/src/com/rubyeventmachine/tests/ConnectTest.java", "java/src/com/rubyeventmachine/tests/EMTest.java", "java/src/com/rubyeventmachine/tests/TestDatagrams.java", "java/src/com/rubyeventmachine/tests/TestServers.java", "java/src/com/rubyeventmachine/tests/TestTimers.java", "lib/em/buftok.rb", "lib/em/callback.rb", "lib/em/channel.rb", "lib/em/connection.rb", "lib/em/deferrable.rb", "lib/em/file_watch.rb", "lib/em/future.rb", "lib/em/messages.rb", "lib/em/process_watch.rb", "lib/em/processes.rb", "lib/em/protocols.rb", "lib/em/protocols/header_and_content.rb", "lib/em/protocols/httpclient.rb", "lib/em/protocols/httpclient2.rb", "lib/em/protocols/line_and_text.rb", "lib/em/protocols/linetext2.rb", "lib/em/protocols/memcache.rb", "lib/em/protocols/object_protocol.rb", "lib/em/protocols/postgres3.rb", "lib/em/protocols/saslauth.rb", "lib/em/protocols/smtpclient.rb", "lib/em/protocols/smtpserver.rb", "lib/em/protocols/socks4.rb", "lib/em/protocols/stomp.rb", "lib/em/protocols/tcptest.rb", "lib/em/queue.rb", "lib/em/spawnable.rb", "lib/em/streamer.rb", "lib/em/timers.rb", "lib/em/version.rb", "lib/eventmachine.rb", "lib/evma.rb", "lib/evma/callback.rb", "lib/evma/container.rb", "lib/evma/factory.rb", "lib/evma/protocol.rb", "lib/evma/reactor.rb", "lib/jeventmachine.rb", "lib/pr_eventmachine.rb", "setup.rb", "tasks/cpp.rake_example", "tests/client.crt", "tests/client.key", "tests/test_attach.rb", "tests/test_basic.rb", "tests/test_channel.rb", "tests/test_connection_count.rb", "tests/test_defer.rb", "tests/test_epoll.rb", "tests/test_error_handler.rb", "tests/test_errors.rb", "tests/test_exc.rb", "tests/test_file_watch.rb", "tests/test_futures.rb", "tests/test_get_sock_opt.rb", "tests/test_handler_check.rb", "tests/test_hc.rb", "tests/test_httpclient.rb", "tests/test_httpclient2.rb", "tests/test_inactivity_timeout.rb", "tests/test_kb.rb", "tests/test_ltp.rb", "tests/test_ltp2.rb", "tests/test_next_tick.rb", "tests/test_object_protocol.rb", "tests/test_pause.rb", "tests/test_pending_connect_timeout.rb", "tests/test_process_watch.rb", "tests/test_processes.rb", "tests/test_proxy_connection.rb", "tests/test_pure.rb", "tests/test_queue.rb", "tests/test_running.rb", "tests/test_sasl.rb", "tests/test_send_file.rb", "tests/test_servers.rb", "tests/test_smtpclient.rb", "tests/test_smtpserver.rb", "tests/test_spawn.rb", "tests/test_ssl_args.rb", "tests/test_ssl_methods.rb", "tests/test_ssl_verify.rb", "tests/test_timers.rb", "tests/test_ud.rb", "tests/testem.rb", "web/whatis"]
  s.homepage = %q{http://rubyeventmachine.com}
  s.rdoc_options = ["--title", "EventMachine", "--main", "README", "--line-numbers", "-x", "lib/em/version", "-x", "lib/emva", "-x", "lib/evma/", "-x", "lib/pr_eventmachine", "-x", "lib/jeventmachine"]
  s.require_paths = ["lib"]
  s.rubyforge_project = %q{eventmachine}
  s.rubygems_version = %q{1.3.5}
  s.summary = %q{Ruby/EventMachine library}

  if s.respond_to? :specification_version then
    current_version = Gem::Specification::CURRENT_SPECIFICATION_VERSION
    s.specification_version = 3

    if Gem::Version.new(Gem::RubyGemsVersion) >= Gem::Version.new('1.2.0') then
    else
    end
  else
  end
end
