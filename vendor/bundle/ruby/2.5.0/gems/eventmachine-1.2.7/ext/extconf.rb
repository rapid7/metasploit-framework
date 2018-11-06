require 'fileutils'
require 'mkmf'

# Eager check devs tools
have_devel? if respond_to?(:have_devel?)

def check_libs libs = [], fatal = false
  libs.all? { |lib| have_library(lib) || (abort("could not find library: #{lib}") if fatal) }
end

def check_heads heads = [], fatal = false
  heads.all? { |head| have_header(head) || (abort("could not find header: #{head}") if fatal)}
end

def add_define(name)
  $defs.push("-D#{name}")
end

##
# OpenSSL:

# override append_library, so it actually appends (instead of prepending)
# this fixes issues with linking ssl, since libcrypto depends on symbols in libssl
def append_library(libs, lib)
  libs + " " + format(LIBARG, lib)
end

SSL_HEADS = %w(openssl/ssl.h openssl/err.h)
SSL_LIBS = %w(crypto ssl)
# OpenSSL 1.1.0 and above for Windows use the Unix library names
# OpenSSL 0.9.8 and 1.0.x for Windows use the *eay32 library names
SSL_LIBS_WIN = RUBY_PLATFORM =~ /mswin|mingw|bccwin/ ? %w(ssleay32 libeay32) : []

def dir_config_wrapper(pretty_name, name, idefault=nil, ldefault=nil)
  inc, lib = dir_config(name, idefault, ldefault)
  if inc && lib
    # TODO: Remove when 2.0.0 is the minimum supported version
    # Ruby versions not incorporating the mkmf fix at
    # https://bugs.ruby-lang.org/projects/ruby-trunk/repository/revisions/39717
    # do not properly search for lib directories, and must be corrected
    unless lib && lib[-3, 3] == 'lib'
      @libdir_basename = 'lib'
      inc, lib = dir_config(name, idefault, ldefault)
    end
    unless idefault && ldefault
      abort "-----\nCannot find #{pretty_name} include path #{inc}\n-----" unless inc && inc.split(File::PATH_SEPARATOR).any? { |dir| File.directory?(dir) }
      abort "-----\nCannot find #{pretty_name} library path #{lib}\n-----" unless lib && lib.split(File::PATH_SEPARATOR).any? { |dir| File.directory?(dir) }
      warn "-----\nUsing #{pretty_name} in path #{File.dirname inc}\n-----"
    end
    true
  end
end

def dir_config_search(pretty_name, name, paths, &b)
  paths.each do |p|
    if dir_config_wrapper('OpenSSL', 'ssl', p + '/include', p + '/lib') && yield
      warn "-----\nFound #{pretty_name} in path #{p}\n-----"
      return true
    end
  end
  false
end

def pkg_config_wrapper(pretty_name, name)
  cflags, ldflags, libs = pkg_config(name)
  unless [cflags, ldflags, libs].any?(&:nil?) || [cflags, ldflags, libs].any?(&:empty?)
    warn "-----\nUsing #{pretty_name} from pkg-config #{cflags} && #{ldflags} && #{libs}\n-----"
    true
  end
end

if ENV['CROSS_COMPILING']
  openssl_version = ENV.fetch("OPENSSL_VERSION", "1.0.2e")
  openssl_dir = File.expand_path("~/.rake-compiler/builds/openssl-#{openssl_version}/")
  if File.exist?(openssl_dir)
    FileUtils.mkdir_p Dir.pwd+"/openssl/"
    FileUtils.cp Dir[openssl_dir+"/include/openssl/*.h"], Dir.pwd+"/openssl/", :verbose => true
    FileUtils.cp Dir[openssl_dir+"/lib*.a"], Dir.pwd, :verbose => true
    $INCFLAGS << " -I#{Dir.pwd}" # for the openssl headers
    add_define "WITH_SSL"
  else
    STDERR.puts
    STDERR.puts "**************************************************************************************"
    STDERR.puts "**** Cross-compiled OpenSSL not found"
    STDERR.puts "**** Run: hg clone http://bitbucket.org/ged/ruby-pg && cd ruby-pg && rake openssl_libs"
    STDERR.puts "**************************************************************************************"
    STDERR.puts
  end
elsif dir_config_wrapper('OpenSSL', 'ssl')
  # If the user has provided a --with-ssl-dir argument, we must respect it or fail.
  add_define 'WITH_SSL' if (check_libs(SSL_LIBS) || check_libs(SSL_LIBS_WIN)) && check_heads(SSL_HEADS)
elsif pkg_config_wrapper('OpenSSL', 'openssl')
  # If we can detect OpenSSL by pkg-config, use it as the next-best option
  add_define 'WITH_SSL' if (check_libs(SSL_LIBS) || check_libs(SSL_LIBS_WIN)) && check_heads(SSL_HEADS)
elsif (check_libs(SSL_LIBS) || check_libs(SSL_LIBS_WIN)) && check_heads(SSL_HEADS)
  # If we don't even need any options to find a usable OpenSSL, go with it
  add_define 'WITH_SSL'
elsif dir_config_search('OpenSSL', 'ssl', ['/usr/local', '/opt/local', '/usr/local/opt/openssl']) do
    (check_libs(SSL_LIBS) || check_libs(SSL_LIBS_WIN)) && check_heads(SSL_HEADS)
  end
  # Finally, look for OpenSSL in alternate locations including MacPorts and HomeBrew
  add_define 'WITH_SSL'
end

add_define 'BUILD_FOR_RUBY'

# Ruby features:

have_var('rb_trap_immediate', ['ruby.h', 'rubysig.h'])
have_func('rb_thread_blocking_region')
have_func('rb_thread_call_without_gvl', 'ruby/thread.h')
have_func('rb_thread_fd_select')
have_type('rb_fdset_t', 'ruby/intern.h')
have_func('rb_wait_for_single_fd')
have_func('rb_enable_interrupt')
have_func('rb_time_new')

# System features:

add_define('HAVE_INOTIFY') if inotify = have_func('inotify_init', 'sys/inotify.h')
add_define('HAVE_OLD_INOTIFY') if !inotify && have_macro('__NR_inotify_init', 'sys/syscall.h')
have_func('writev', 'sys/uio.h')
have_func('pipe2', 'unistd.h')
have_func('accept4', 'sys/socket.h')
have_const('SOCK_CLOEXEC', 'sys/socket.h')

# Minor platform details between *nix and Windows:

if RUBY_PLATFORM =~ /(mswin|mingw|bccwin)/
  GNU_CHAIN = ENV['CROSS_COMPILING'] || $1 == 'mingw'
  OS_WIN32 = true
  add_define "OS_WIN32"
else
  GNU_CHAIN = true
  OS_UNIX = true
  add_define 'OS_UNIX'

  add_define "HAVE_KQUEUE" if have_header("sys/event.h") && have_header("sys/queue.h")
end

# Adjust number of file descriptors (FD) on Windows

if RbConfig::CONFIG["host_os"] =~ /mingw/
  found = RbConfig::CONFIG.values_at("CFLAGS", "CPPFLAGS").
    any? { |v| v.include?("FD_SETSIZE") }

  add_define "FD_SETSIZE=32767" unless found
end

# Main platform invariances:

case RUBY_PLATFORM
when /mswin32/, /mingw32/, /bccwin32/
  check_heads(%w[windows.h winsock.h], true)
  check_libs(%w[kernel32 rpcrt4 gdi32], true)

  if GNU_CHAIN
    CONFIG['LDSHAREDXX'] = "$(CXX) -shared -static-libgcc -static-libstdc++"
  else
    $defs.push "-EHs"
    $defs.push "-GR"
  end

  # Newer versions of Ruby already define _WIN32_WINNT, which is needed
  # to get access to newer POSIX networking functions (e.g. getaddrinfo)
  add_define '_WIN32_WINNT=0x0501' unless have_func('getaddrinfo')

when /solaris/
  add_define 'OS_SOLARIS8'
  check_libs(%w[nsl socket], true)

  # If Ruby was compiled for 32-bits, then select() can only handle 1024 fds
  # There is an alternate function, select_large_fdset, that supports more.
  have_func('select_large_fdset', 'sys/select.h')

  if CONFIG['CC'] == 'cc' && (
     `cc -flags 2>&1` =~ /Sun/ || # detect SUNWspro compiler
     `cc -V 2>&1` =~ /Sun/        # detect Solaris Studio compiler
    )
    # SUN CHAIN
    add_define 'CC_SUNWspro'
    $preload = ["\nCXX = CC"] # hack a CXX= line into the makefile
    $CFLAGS = CONFIG['CFLAGS'] = "-KPIC"
    CONFIG['CCDLFLAGS'] = "-KPIC"
    CONFIG['LDSHARED'] = "$(CXX) -G -KPIC -lCstd"
    CONFIG['LDSHAREDXX'] = "$(CXX) -G -KPIC -lCstd"
  else
    # GNU CHAIN
    # on Unix we need a g++ link, not gcc.
    CONFIG['LDSHARED'] = "$(CXX) -shared"
  end

when /openbsd/
  # OpenBSD branch contributed by Guillaume Sellier.

  # on Unix we need a g++ link, not gcc. On OpenBSD, linking against libstdc++ have to be explicitly done for shared libs
  CONFIG['LDSHARED'] = "$(CXX) -shared -lstdc++ -fPIC"
  CONFIG['LDSHAREDXX'] = "$(CXX) -shared -lstdc++ -fPIC"

when /darwin/
  add_define 'OS_DARWIN'

  # on Unix we need a g++ link, not gcc.
  # Ff line contributed by Daniel Harple.
  CONFIG['LDSHARED'] = "$(CXX) " + CONFIG['LDSHARED'].split[1..-1].join(' ')

when /linux/
  add_define 'HAVE_EPOLL' if have_func('epoll_create', 'sys/epoll.h')

  # on Unix we need a g++ link, not gcc.
  CONFIG['LDSHARED'] = "$(CXX) -shared"

when /aix/
  CONFIG['LDSHARED'] = "$(CXX) -Wl,-bstatic -Wl,-bdynamic -Wl,-G -Wl,-brtl"

when /cygwin/
  # For rubies built with Cygwin, CXX may be set to CC, which is just
  # a wrapper for gcc.
  # This will compile, but it will not link to the C++ std library.
  # Explicitly set CXX to use g++.
  CONFIG['CXX'] = "g++"
  # on Unix we need a g++ link, not gcc.
  CONFIG['LDSHARED'] = "$(CXX) -shared"

else
  # on Unix we need a g++ link, not gcc.
  CONFIG['LDSHARED'] = "$(CXX) -shared"
end

# Platform-specific time functions
if have_func('clock_gettime')
  # clock_gettime is POSIX, but the monotonic clocks are not
  have_const('CLOCK_MONOTONIC_RAW', 'time.h') # Linux
  have_const('CLOCK_MONOTONIC', 'time.h') # Linux, Solaris, BSDs
else
  have_func('gethrtime') # Older Solaris and HP-UX
end

# Hack so that try_link will test with a C++ compiler instead of a C compiler
TRY_LINK.sub!('$(CC)', '$(CXX)')

# This is our wishlist. We use whichever flags work on the host.
# In the future, add -Werror to make sure all warnings are resolved.
# deprecated-declarations are used in OS X OpenSSL
# ignored-qualifiers are used by the Bindings (would-be void *)
# unused-result because GCC 4.6 no longer silences (void) ignore_this(function)
# address because on Windows, rb_fd_select checks if &fds is non-NULL, which it cannot be
%w(
  -Wall
  -Wextra
  -Wno-deprecated-declarations
  -Wno-ignored-qualifiers
  -Wno-unused-result
  -Wno-address
).select do |flag|
  try_link('int main() {return 0;}', flag)
end.each do |flag|
  CONFIG['CXXFLAGS'] << ' ' << flag
end
puts "CXXFLAGS=#{CONFIG['CXXFLAGS']}"

# Solaris C++ compiler doesn't have make_pair()
add_define 'HAVE_MAKE_PAIR' if try_link(<<SRC, '-lstdc++')
  #include <utility>
  using namespace std;
  int main(){ pair<const int,int> tuple = make_pair(1,2); }
SRC
TRY_LINK.sub!('$(CXX)', '$(CC)')

create_makefile "rubyeventmachine"
