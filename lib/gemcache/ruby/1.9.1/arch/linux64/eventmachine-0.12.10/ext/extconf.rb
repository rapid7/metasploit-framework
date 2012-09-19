require 'mkmf'

def check_libs libs = [], fatal = false
  libs.all? { |lib| have_library(lib) || (abort("could not find library: #{lib}") if fatal) }
end

def check_heads heads = [], fatal = false
  heads.all? { |head| have_header(head) || (abort("could not find header: #{head}") if fatal)}
end

def add_define(name)
  $defs.push("-D#{name}")
end

add_define 'BUILD_FOR_RUBY'
add_define 'HAVE_RBTRAP' if have_var('rb_trap_immediate', ['ruby.h', 'rubysig.h'])
add_define "HAVE_TBR" if have_func('rb_thread_blocking_region')# and have_macro('RUBY_UBF_IO', 'ruby.h')
add_define "HAVE_INOTIFY" if inotify = have_func('inotify_init', 'sys/inotify.h')
add_define "HAVE_OLD_INOTIFY" if !inotify && have_macro('__NR_inotify_init', 'sys/syscall.h')
add_define 'HAVE_WRITEV' if have_func('writev', 'sys/uio.h')
have_func('rb_thread_check_ints')
have_func('rb_time_new')

# Minor platform details between *nix and Windows:

if RUBY_PLATFORM =~ /(mswin|mingw|bccwin)/
  GNU_CHAIN = $1 == 'mingw'
  OS_WIN32 = true
  add_define "OS_WIN32"
else
  GNU_CHAIN = true
  OS_UNIX = true
  add_define 'OS_UNIX'

  add_define "HAVE_KQUEUE" if have_header("sys/event.h") and have_header("sys/queue.h")
end

# Main platform invariances:

case RUBY_PLATFORM
when /mswin32/, /mingw32/, /bccwin32/
  check_heads(%w[windows.h winsock.h], true)
  check_libs(%w[kernel32 rpcrt4 gdi32], true)

  if GNU_CHAIN
    CONFIG['LDSHARED'] = "$(CXX) -shared -lstdc++"
  else
    $defs.push "-EHs"
    $defs.push "-GR"
  end

when /solaris/
  add_define 'OS_SOLARIS8'
  check_libs(%w[nsl socket], true)

  # Patch by Tim Pease, fixes SUNWspro compile problems.
  if CONFIG['CC'] == 'cc'
    # SUN CHAIN
    $CFLAGS = CONFIG['CFLAGS'] = "-KPIC -G"
    CONFIG['CCDLFLAGS'] = "-KPIC"
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
  # on Unix we need a g++ link, not gcc.
  # Ff line contributed by Daniel Harple.
  CONFIG['LDSHARED'] = "$(CXX) " + CONFIG['LDSHARED'].split[1..-1].join(' ')

when /linux/
  add_define 'HAVE_EPOLL' if have_func('epoll_create', 'sys/epoll.h')

  # Original epoll test is inadequate because 2.4 kernels have the header
  # but not the code.
  # add_define 'HAVE_EPOLL' if have_header('sys/epoll.h')
  # if have_header('sys/epoll.h')
  #   File.open("hasEpollTest.c", "w") {|f|
  #     f.puts "#include <sys/epoll.h>"
  #     f.puts "int main() { epoll_create(1024); return 0;}"
  #   }
  #   (e = system( "gcc hasEpollTest.c -o hasEpollTest " )) and (e = $?.to_i)
  #   `rm -f hasEpollTest.c hasEpollTest`
  #   add_define 'HAVE_EPOLL' if e == 0
  # end

  # on Unix we need a g++ link, not gcc.
  CONFIG['LDSHARED'] = "$(CXX) -shared"

when /aix/
  CONFIG['LDSHARED'] = "$(CXX) -shared -Wl,-G -Wl,-brtl"

else
  # on Unix we need a g++ link, not gcc.
  CONFIG['LDSHARED'] = "$(CXX) -shared"
end

# OpenSSL:

def manual_ssl_config
  ssl_libs_heads_args = {
    :unix => [%w[ssl crypto], %w[openssl/ssl.h openssl/err.h]],
    :darwin => [%w[ssl crypto C], %w[openssl/ssl.h openssl/err.h]],
    # openbsd and linux:
    :crypto_hack => [%w[crypto ssl crypto], %w[openssl/ssl.h openssl/err.h]],
    :mswin => [%w[ssleay32 libeay32], %w[openssl/ssl.h openssl/err.h]],
  }

  dc_flags = ['ssl']
  dc_flags += ["#{ENV['OPENSSL']}/include", ENV['OPENSSL']] if /linux/ =~ RUBY_PLATFORM

  libs, heads = case RUBY_PLATFORM
  when /mswin/    ; ssl_libs_heads_args[:mswin]
  when /mingw/    ; ssl_libs_heads_args[:unix]
  when /darwin/   ; ssl_libs_heads_args[:darwin]
  when /openbsd/  ; ssl_libs_heads_args[:crypto_hack]
  when /linux/    ; ssl_libs_heads_args[:crypto_hack]
  else              ssl_libs_heads_args[:unix]
  end
  dir_config(*dc_flags)
  check_libs(libs) and check_heads(heads)
end

# Try to use pkg_config first, fixes #73
if pkg_config('openssl') || manual_ssl_config
  add_define "WITH_SSL"
else
  add_define "WITHOUT_SSL"
end

# solaris c++ compiler doesn't have make_pair()
TRY_LINK.sub!('$(CC)', '$(CXX)')
add_define 'HAVE_MAKE_PAIR' if try_link(<<SRC, '-lstdc++')
  #include <utility>
  using namespace std;
  int main(){ pair<int,int> tuple = make_pair(1,2); }
SRC
TRY_LINK.sub!('$(CXX)', '$(CC)')

create_makefile "rubyeventmachine"