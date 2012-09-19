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

# Minor platform details between *nix and Windows:

if RUBY_PLATFORM =~ /(mswin|mingw|bccwin)/
  GNU_CHAIN = $1 == 'mingw'
  OS_WIN32 = true
  add_define "OS_WIN32"
else
  GNU_CHAIN = true
  OS_UNIX = true
  add_define 'OS_UNIX'
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
  # on Unix we need a g++ link, not gcc.
  CONFIG['LDSHARED'] = "$(CXX) -shared"

when /aix/
  # on Unix we need a g++ link, not gcc.
  CONFIG['LDSHARED'] = "$(CXX) -shared -Wl,-G"

else
  # on Unix we need a g++ link, not gcc.
  CONFIG['LDSHARED'] = "$(CXX) -shared"
end

create_makefile "fastfilereaderext"