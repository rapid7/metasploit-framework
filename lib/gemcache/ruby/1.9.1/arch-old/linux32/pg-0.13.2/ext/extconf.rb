require 'pp'
require 'mkmf'


if ENV['MAINTAINER_MODE']
	$stderr.puts "Maintainer mode enabled."
	$CFLAGS <<
		' -Wall' <<
		' -ggdb' <<
		' -DDEBUG' <<
		' -pedantic'
end

if pgdir = with_config( 'pg' )
	ENV['PATH'] = "#{pgdir}/bin" + File::PATH_SEPARATOR + ENV['PATH']
end

if ENV['CROSS_COMPILING']
	$LDFLAGS << " -L#{CONFIG['libdir']}"

	# Link against all required libraries for static build, if they are available
	have_library( 'gdi32', 'CreateDC' ) && append_library( $libs, 'gdi32' )
	have_library( 'secur32' ) && append_library( $libs, 'secur32' )
	have_library( 'ws2_32', 'WSASocket') && append_library( $libs, 'ws2_32' )
	have_library( 'crypto', 'BIO_new' ) && append_library( $libs, 'crypto' )
	have_library( 'ssl', 'SSL_new' ) && append_library( $libs, 'ssl' )
end

dir_config 'pg'

if pgconfig = ( with_config('pg-config') || with_config('pg_config') || find_executable('pg_config') )
	$stderr.puts "Using config values from %s" % [ pgconfig ]
	$CPPFLAGS << " -I%s" % [ `"#{pgconfig}" --includedir`.chomp ]
	$LDFLAGS << " -L%s" % [ `"#{pgconfig}" --libdir`.chomp ]
else
	$stderr.puts "No pg_config... trying anyway. If building fails, please try again with",
		" --with-pg-config=/path/to/pg_config"
end

find_header( 'libpq-fe.h' ) or abort "Can't find the 'libpq-fe.h header"
find_header( 'libpq/libpq-fs.h' ) or abort "Can't find the 'libpq/libpq-fs.h header"
find_header( 'pg_config_manual.h' ) or abort "Can't find the 'pg_config_manual.h' header"

abort "Can't find the PostgreSQL client library (libpq)" unless
	have_library( 'pq', 'PQconnectdb', ['libpq-fe.h'] ) ||
	have_library( 'libpq', 'PQconnectdb', ['libpq-fe.h'] ) ||
	have_library( 'ms/libpq', 'PQconnectdb', ['libpq-fe.h'] )

# optional headers/functions
have_func 'PQconnectionUsedPassword' or
	abort "Your PostgreSQL is too old. Either install an older version " +
	      "of this gem or upgrade your database."
have_func 'PQisthreadsafe'
have_func 'PQprepare'
have_func 'PQexecParams'
have_func 'PQescapeString'
have_func 'PQescapeStringConn'
have_func 'PQgetCancel'
have_func 'lo_create'
have_func 'pg_encoding_to_char'
have_func 'pg_char_to_encoding'
have_func 'PQsetClientEncoding'

have_func 'rb_encdb_alias'
have_func 'rb_enc_alias'

$defs.push( "-DHAVE_ST_NOTIFY_EXTRA" ) if
	have_struct_member 'struct pgNotify', 'extra', 'libpq-fe.h'

# unistd.h confilicts with ruby/win32.h when cross compiling for win32 and ruby 1.9.1
have_header 'unistd.h'
have_header 'ruby/st.h' or have_header 'st.h' or abort "pg currently requires the ruby/st.h header"

create_header()
create_makefile( "pg_ext" )

