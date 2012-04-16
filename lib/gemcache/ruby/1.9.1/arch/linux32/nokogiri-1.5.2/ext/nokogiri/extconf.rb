ENV['RC_ARCHS'] = '' if RUBY_PLATFORM =~ /darwin/

# :stopdoc:

require 'mkmf'

RbConfig::MAKEFILE_CONFIG['CC'] = ENV['CC'] if ENV['CC']

ROOT = File.expand_path(File.join(File.dirname(__FILE__), '..', '..'))
LIBDIR = Config::CONFIG['libdir']
INCLUDEDIR = Config::CONFIG['includedir']

if defined?(RUBY_ENGINE) && RUBY_ENGINE == 'macruby'
  $LIBRUBYARG_STATIC.gsub!(/-static/, '')
end

$CFLAGS << " #{ENV["CFLAGS"]}"
$LIBS << " #{ENV["LIBS"]}"

if RbConfig::CONFIG['target_os'] == 'mingw32' || RbConfig::CONFIG['target_os'] =~ /mswin/
  $CFLAGS << " -DXP_WIN -DXP_WIN32 -DUSE_INCLUDED_VASPRINTF"
elsif RbConfig::CONFIG['target_os'] =~ /solaris/
  $CFLAGS << " -DUSE_INCLUDED_VASPRINTF"
else
  $CFLAGS << " -g -DXP_UNIX"
end

if RbConfig::MAKEFILE_CONFIG['CC'] =~ /mingw/
  $CFLAGS << " -DIN_LIBXML"
end

if RbConfig::MAKEFILE_CONFIG['CC'] =~ /gcc/
  $CFLAGS << " -O3" unless $CFLAGS[/-O\d/]
  $CFLAGS << " -Wall -Wcast-qual -Wwrite-strings -Wconversion -Wmissing-noreturn -Winline"
end

if RbConfig::CONFIG['target_os'] =~ /mswin/
  lib_prefix = 'lib'

  # There's no default include/lib dir on Windows. Let's just add the Ruby ones
  # and resort on the search path specified by INCLUDE and LIB environment
  # variables
  HEADER_DIRS = [INCLUDEDIR]
  LIB_DIRS = [LIBDIR]
  XML2_HEADER_DIRS = [File.join(INCLUDEDIR, "libxml2"), INCLUDEDIR]

else
  lib_prefix = ''

  HEADER_DIRS = [
    # First search /opt/local for macports
    '/opt/local/include',

    # Then search /usr/local for people that installed from source
    '/usr/local/include',

    # Check the ruby install locations
    INCLUDEDIR,

    # Finally fall back to /usr
    '/usr/include',
    '/usr/include/libxml2',
  ]

  LIB_DIRS = [
    # First search /opt/local for macports
    '/opt/local/lib',

    # Then search /usr/local for people that installed from source
    '/usr/local/lib',

    # Check the ruby install locations
    LIBDIR,

    # Finally fall back to /usr
    '/usr/lib',
  ]

  XML2_HEADER_DIRS = [
    '/opt/local/include/libxml2',
    '/usr/local/include/libxml2',
    File.join(INCLUDEDIR, "libxml2")
  ] + HEADER_DIRS

  # If the user has homebrew installed, use the libxml2 inside homebrew
  brew_prefix = `brew --prefix libxml2 2> /dev/null`.chomp
  unless brew_prefix.empty?
    LIB_DIRS.unshift File.join(brew_prefix, 'lib')
    XML2_HEADER_DIRS.unshift File.join(brew_prefix, 'include/libxml2')
  end
end

dir_config('zlib', HEADER_DIRS, LIB_DIRS)
dir_config('iconv', HEADER_DIRS, LIB_DIRS)
dir_config('xml2', XML2_HEADER_DIRS, LIB_DIRS)
dir_config('xslt', HEADER_DIRS, LIB_DIRS)

def asplode(lib)
  abort "-----\n#{lib} is missing.  please visit http://nokogiri.org/tutorials/installing_nokogiri.html for help with installing dependencies.\n-----"
end

pkg_config('libxslt') if RUBY_PLATFORM =~ /mingw/

asplode "libxml2"  unless find_header('libxml/parser.h')
asplode "libxslt"  unless find_header('libxslt/xslt.h')
asplode "libexslt" unless find_header('libexslt/exslt.h')
asplode "libiconv" unless have_func('iconv_open', 'iconv.h') or have_library('iconv', 'iconv_open', 'iconv.h')
asplode "libxml2"  unless find_library("#{lib_prefix}xml2", 'xmlParseDoc')
asplode "libxslt"  unless find_library("#{lib_prefix}xslt", 'xsltParseStylesheetDoc')
asplode "libexslt" unless find_library("#{lib_prefix}exslt", 'exsltFuncRegister')

unless have_func('xmlHasFeature')
  abort "-----\nThe function 'xmlHasFeature' is missing from your installation of libxml2.  Likely this means that your installed version of libxml2 is old enough that nokogiri will not work well.  To get around this problem, please upgrade your installation of libxml2.

Please visit http://nokogiri.org/tutorials/installing_nokogiri.html for more help!"
end

have_func 'xmlFirstElementChild'
have_func('xmlRelaxNGSetParserStructuredErrors')
have_func('xmlRelaxNGSetParserStructuredErrors')
have_func('xmlRelaxNGSetValidStructuredErrors')
have_func('xmlSchemaSetValidStructuredErrors')
have_func('xmlSchemaSetParserStructuredErrors')

if ENV['CPUPROFILE']
  unless find_library('profiler', 'ProfilerEnable', *LIB_DIRS)
    abort "google performance tools are not installed"
  end
end

create_makefile('nokogiri/nokogiri')
# :startdoc:
