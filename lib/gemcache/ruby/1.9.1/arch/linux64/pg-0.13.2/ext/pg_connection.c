/*
 * pg_connection.c - PG::Connection class extension
 * $Id: pg_connection.c,v 679b1db2b430 2012/02/12 20:50:47 ged $
 *
 */

#include "pg.h"


/********************************************************************
 * 
 * Document-class: PG::Connection
 *
 * The class to access PostgreSQL RDBMS, based on the libpq interface, 
 * provides convenient OO methods to interact with PostgreSQL.
 *
 * For example, to send query to the database on the localhost:
 *    require 'pg'
 *    conn = PG::Connection.open(:dbname => 'test')
 *    res = conn.exec('SELECT $1 AS a, $2 AS b, $3 AS c',[1, 2, nil])
 *    # Equivalent to:
 *    #  res  = conn.exec('SELECT 1 AS a, 2 AS b, NULL AS c')
 *
 * See the PGresult class for information on working with the results of a query.
 *
 */
VALUE rb_cPGconn;

static PQnoticeReceiver default_notice_receiver = NULL;
static PQnoticeProcessor default_notice_processor = NULL;

static PGconn *pgconn_check( VALUE );
static VALUE pgconn_finish( VALUE );


/*
 * Global functions
 */

/*
 * Fetch the data pointer and check it for sanity.
 */
PGconn *
pg_get_pgconn( VALUE self )
{
	PGconn *conn = pgconn_check( self );

	if ( !conn )
		rb_raise( rb_ePGerror, "connection is closed" );

	return conn;
}


/*
 * Allocation/
 */

/*
 * Object validity checker. Returns the data pointer.
 */
static PGconn *
pgconn_check( VALUE self ) {

	Check_Type( self, T_DATA );

    if ( !rb_obj_is_kind_of(self, rb_cPGconn) ) {
		rb_raise( rb_eTypeError, "wrong argument type %s (expected PG::Connection)",
				  rb_obj_classname( self ) );
    }

	return DATA_PTR( self );
}


/*
 * GC Free function
 */
static void
pgconn_gc_free( PGconn *conn )
{
	if (conn != NULL)
		PQfinish( conn );
}


/**************************************************************************
 * Class Methods
 **************************************************************************/

/*
 * Document-method: allocate
 * 
 * call-seq:
 *   PG::Connection.allocate -> conn
 */
static VALUE
pgconn_s_allocate( VALUE klass )
{
	return Data_Wrap_Struct( klass, NULL, pgconn_gc_free, NULL );
}


/*
 * Document-method: new
 *
 * call-seq:
 *    PG::Connection.new -> conn
 *    PG::Connection.new(connection_hash) -> conn
 *    PG::Connection.new(connection_string) -> conn
 *    PG::Connection.new(host, port, options, tty, dbname, user, password) ->  conn
 * 
 * Create a connection to the specified server.
 * 
 * [+host+]
 *   server hostname
 * [+hostaddr+]
 *   server address (avoids hostname lookup, overrides +host+)
 * [+port+]
 *   server port number
 * [+dbname+]
 *   connecting database name
 * [+user+]
 *   login user name
 * [+password+]
 *   login password
 * [+connect_timeout+]
 *   maximum time to wait for connection to succeed
 * [+options+]
 *   backend options
 * [+tty+]
 *   (ignored in newer versions of PostgreSQL)
 * [+sslmode+]
 *   (disable|allow|prefer|require)
 * [+krbsrvname+]
 *   kerberos service name
 * [+gsslib+]
 *   GSS library to use for GSSAPI authentication
 * [+service+]
 *   service name to use for additional parameters
 * 
 * Examples:
 * 
 *   # Connect using all defaults
 *   PG::Connection.new
 *
 *   # As a Hash
 *   PG::Connection.new( :dbname => 'test', :port => 5432 )
 *   
 *   # As a String
 *   PG::Connection.new( "dbname=test port=5432" )
 *   
 *   # As an Array
 *   PG::Connection.new( nil, 5432, nil, nil, 'test', nil, nil )
 *  
 * If the Ruby default internal encoding is set (i.e., Encoding.default_internal != nil), the
 * connection will have its +client_encoding+ set accordingly.
 * 
 * Raises a PG::Error if the connection fails.
 */
static VALUE
pgconn_init(int argc, VALUE *argv, VALUE self)
{
	PGconn *conn = NULL;
	VALUE conninfo;
	VALUE error;
#ifdef M17N_SUPPORTED	
	rb_encoding *enc;
	const char *encname;
#endif

	conninfo = rb_funcall2( rb_cPGconn, rb_intern("parse_connect_args"), argc, argv );
	conn = PQconnectdb(StringValuePtr(conninfo));

	if(conn == NULL)
		rb_raise(rb_ePGerror, "PQconnectStart() unable to allocate structure");

	Check_Type(self, T_DATA);
	DATA_PTR(self) = conn;

	if (PQstatus(conn) == CONNECTION_BAD) {
		error = rb_exc_new2(rb_ePGerror, PQerrorMessage(conn));
		rb_iv_set(error, "@connection", self);
		rb_exc_raise(error);
	}

#ifdef M17N_SUPPORTED
	/* If Ruby has its Encoding.default_internal set, set PostgreSQL's client_encoding 
	 * to match */
	if (( enc = rb_default_internal_encoding() )) {
		encname = pg_get_rb_encoding_as_pg_encoding( enc );
		if ( PQsetClientEncoding(conn, encname) != 0 )
			rb_warn( "Failed to set the default_internal encoding to %s: '%s'",
			         encname, PQerrorMessage(conn) );
	}
#endif

	if (rb_block_given_p()) {
		return rb_ensure(rb_yield, self, pgconn_finish, self);
	}
	return self;
}

/*
 * call-seq:
 *    PG::Connection.connect_start(connection_hash)       -> conn
 *    PG::Connection.connect_start(connection_string)     -> conn
 *    PG::Connection.connect_start(host, port, options, tty, dbname, login, password) ->  conn
 *
 * This is an asynchronous version of PG::Connection.connect().
 *
 * Use #connect_poll to poll the status of the connection.
 *
 * NOTE: this does *not* set the connection's +client_encoding+ for you if 
 * Encoding.default_internal is set. To set it after the connection is established, 
 * call #internal_encoding=. You can also set it automatically by setting 
 * ENV['PGCLIENTENCODING'], or include the 'options' connection parameter.
 * 
 */
static VALUE
pgconn_s_connect_start( int argc, VALUE *argv, VALUE klass )
{
	PGconn *conn = NULL;
	VALUE rb_conn;
	VALUE conninfo;
	VALUE error;

	/*
	 * PG::Connection.connect_start must act as both alloc() and initialize()
	 * because it is not invoked by calling new().
	 */
	rb_conn  = pgconn_s_allocate( klass );
	conninfo = rb_funcall2( klass, rb_intern("parse_connect_args"), argc, argv );
	conn     = PQconnectStart( StringValuePtr(conninfo) );

	if( conn == NULL )
		rb_raise(rb_ePGerror, "PQconnectStart() unable to allocate structure");

	Check_Type(rb_conn, T_DATA);
	DATA_PTR(rb_conn) = conn;

	if ( PQstatus(conn) == CONNECTION_BAD ) {
		error = rb_exc_new2(rb_ePGerror, PQerrorMessage(conn));
		rb_iv_set(error, "@connection", rb_conn);
		rb_exc_raise(error);
	}

	if ( rb_block_given_p() ) {
		return rb_ensure( rb_yield, rb_conn, pgconn_finish, rb_conn );
	}
	return rb_conn;
}

/*
 * call-seq:
 *    PG::Connection.conndefaults() -> Array
 *
 * Returns an array of hashes. Each hash has the keys:
 * [+:keyword+]
 *   the name of the option
 * [+:envvar+]
 *   the environment variable to fall back to
 * [+:compiled+]
 *   the compiled in option as a secondary fallback
 * [+:val+]
 *   the option's current value, or +nil+ if not known
 * [+:label+]
 *   the label for the field
 * [+:dispchar+]
 *   "" for normal, "D" for debug, and "*" for password
 * [+:dispsize+]
 *   field size
 */
static VALUE
pgconn_s_conndefaults(VALUE self)
{
	PQconninfoOption *options = PQconndefaults();
	VALUE ary = rb_ary_new();
	VALUE hash;
	int i = 0;

	UNUSED( self );

	for(i = 0; options[i].keyword != NULL; i++) {
		hash = rb_hash_new();
		if(options[i].keyword)
			rb_hash_aset(hash, ID2SYM(rb_intern("keyword")), rb_str_new2(options[i].keyword));
		if(options[i].envvar)
			rb_hash_aset(hash, ID2SYM(rb_intern("envvar")), rb_str_new2(options[i].envvar));
		if(options[i].compiled)
			rb_hash_aset(hash, ID2SYM(rb_intern("compiled")), rb_str_new2(options[i].compiled));
		if(options[i].val)
			rb_hash_aset(hash, ID2SYM(rb_intern("val")), rb_str_new2(options[i].val));
		if(options[i].label)
			rb_hash_aset(hash, ID2SYM(rb_intern("label")), rb_str_new2(options[i].label));
		if(options[i].dispchar)
			rb_hash_aset(hash, ID2SYM(rb_intern("dispchar")), rb_str_new2(options[i].dispchar));
		rb_hash_aset(hash, ID2SYM(rb_intern("dispsize")), INT2NUM(options[i].dispsize));
		rb_ary_push(ary, hash);
	}
	PQconninfoFree(options);
	return ary;
}


/*
 * call-seq:
 *    PG::Connection.encrypt_password( password, username ) -> String
 *
 * This function is intended to be used by client applications that
 * send commands like: +ALTER USER joe PASSWORD 'pwd'+.
 * The arguments are the cleartext password, and the SQL name 
 * of the user it is for.
 *
 * Return value is the encrypted password.
 */
static VALUE
pgconn_s_encrypt_password(VALUE self, VALUE password, VALUE username)
{
	char *encrypted = NULL;
	VALUE rval = Qnil;

	UNUSED( self );

	Check_Type(password, T_STRING);
	Check_Type(username, T_STRING);

	encrypted = PQencryptPassword(StringValuePtr(password), StringValuePtr(username));
	rval = rb_str_new2( encrypted );
	PQfreemem( encrypted );

	OBJ_INFECT( rval, password );
	OBJ_INFECT( rval, username );

	return rval;
}


/*
 * call-seq:
 *    PG::Connection.isthreadsafe() -> Boolean
 *
 * Returns +true+ if libpq is thread safe, +false+ otherwise.
 */
static VALUE
pgconn_s_isthreadsafe(VALUE self)
{
	UNUSED( self );
	return PQisthreadsafe() ? Qtrue : Qfalse;
}

/**************************************************************************
 * PG::Connection INSTANCE METHODS
 **************************************************************************/

/*
 * call-seq:
 *    conn.connect_poll() -> Fixnum
 *
 * Returns one of:
 * [+PGRES_POLLING_READING+]
 *   wait until the socket is ready to read
 * [+PGRES_POLLING_WRITING+]
 *   wait until the socket is ready to write
 * [+PGRES_POLLING_FAILED+]
 *   the asynchronous connection has failed
 * [+PGRES_POLLING_OK+]
 *   the asynchronous connection is ready
 *
 * Example:
 *   conn = PG::Connection.connect_start("dbname=mydatabase")
 *   socket = IO.for_fd(conn.socket)
 *   status = conn.connect_poll
 *   while(status != PG::PGRES_POLLING_OK) do
 *     # do some work while waiting for the connection to complete
 *     if(status == PG::PGRES_POLLING_READING)
 *       if(not select([socket], [], [], 10.0))
 *         raise "Asynchronous connection timed out!"
 *       end
 *     elsif(status == PG::PGRES_POLLING_WRITING)
 *       if(not select([], [socket], [], 10.0))
 *         raise "Asynchronous connection timed out!"
 *       end
 *     end
 *     status = conn.connect_poll
 *   end
 *   # now conn.status == CONNECTION_OK, and connection
 *   # is ready.
 */
static VALUE
pgconn_connect_poll(VALUE self)
{
	PostgresPollingStatusType status;
	status = PQconnectPoll(pg_get_pgconn(self));
	return INT2FIX((int)status);
}

/*
 * call-seq:
 *    conn.finish
 *
 * Closes the backend connection.
 */
static VALUE
pgconn_finish(VALUE self)
{
	PQfinish(pg_get_pgconn(self));
	DATA_PTR(self) = NULL;
	return Qnil;
}


/*
 * call-seq:
 *    conn.finished?      -> boolean
 *
 * Returns +true+ if the backend connection has been closed.
 */
static VALUE
pgconn_finished_p( VALUE self )
{
	if ( DATA_PTR(self) ) return Qfalse;
	return Qtrue;
}


/*
 * call-seq:
 *    conn.reset()
 *
 * Resets the backend connection. This method closes the 
 * backend connection and tries to re-connect.
 */
static VALUE
pgconn_reset(VALUE self)
{
	PQreset(pg_get_pgconn(self));
	return self;
}

/*
 * call-seq:
 *    conn.reset_start() -> nil
 *
 * Initiate a connection reset in a nonblocking manner.
 * This will close the current connection and attempt to
 * reconnect using the same connection parameters.
 * Use #reset_poll to check the status of the 
 * connection reset.
 */
static VALUE
pgconn_reset_start(VALUE self)
{
	if(PQresetStart(pg_get_pgconn(self)) == 0)
		rb_raise(rb_ePGerror, "reset has failed");
	return Qnil;
}

/*
 * call-seq:
 *    conn.reset_poll -> Fixnum
 *
 * Checks the status of a connection reset operation.
 * See #connect_start and #connect_poll for
 * usage information and return values.
 */
static VALUE
pgconn_reset_poll(VALUE self)
{
	PostgresPollingStatusType status;
	status = PQresetPoll(pg_get_pgconn(self));
	return INT2FIX((int)status);
}

/*
 * call-seq:
 *    conn.db()
 *
 * Returns the connected database name.
 */
static VALUE
pgconn_db(VALUE self)
{
	char *db = PQdb(pg_get_pgconn(self));
	if (!db) return Qnil;
	return rb_tainted_str_new2(db);
}

/*
 * call-seq:
 *    conn.user()
 *
 * Returns the authenticated user name.
 */
static VALUE
pgconn_user(VALUE self)
{
	char *user = PQuser(pg_get_pgconn(self));
	if (!user) return Qnil;
	return rb_tainted_str_new2(user);
}

/*
 * call-seq:
 *    conn.pass()
 *
 * Returns the authenticated user name.
 */
static VALUE
pgconn_pass(VALUE self)
{
	char *user = PQpass(pg_get_pgconn(self));
	if (!user) return Qnil;
	return rb_tainted_str_new2(user);
}

/*
 * call-seq:
 *    conn.host()
 *
 * Returns the connected server name.
 */
static VALUE
pgconn_host(VALUE self)
{
	char *host = PQhost(pg_get_pgconn(self));
	if (!host) return Qnil;
	return rb_tainted_str_new2(host);
}

/*
 * call-seq:
 *    conn.port()
 *
 * Returns the connected server port number.
 */
static VALUE
pgconn_port(VALUE self)
{
	char* port = PQport(pg_get_pgconn(self));
	return INT2NUM(atol(port));
}

/*
 * call-seq:
 *    conn.tty()
 *
 * Returns the connected pgtty. (Obsolete)
 */
static VALUE
pgconn_tty(VALUE self)
{
	char *tty = PQtty(pg_get_pgconn(self));
	if (!tty) return Qnil;
	return rb_tainted_str_new2(tty);
}

/*
 * call-seq:
 *    conn.options()
 *
 * Returns backend option string.
 */
static VALUE
pgconn_options(VALUE self)
{
	char *options = PQoptions(pg_get_pgconn(self));
	if (!options) return Qnil;
	return rb_tainted_str_new2(options);
}

/*
 * call-seq:
 *    conn.status()
 *
 * Returns status of connection : CONNECTION_OK or CONNECTION_BAD
 */
static VALUE
pgconn_status(VALUE self)
{
	return INT2NUM(PQstatus(pg_get_pgconn(self)));
}

/*
 * call-seq:
 *    conn.transaction_status()
 *
 * returns one of the following statuses:
 *   PQTRANS_IDLE    = 0 (connection idle)
 *   PQTRANS_ACTIVE  = 1 (command in progress)
 *   PQTRANS_INTRANS = 2 (idle, within transaction block)
 *   PQTRANS_INERROR = 3 (idle, within failed transaction)
 *   PQTRANS_UNKNOWN = 4 (cannot determine status)
 */
static VALUE
pgconn_transaction_status(VALUE self)
{
	return INT2NUM(PQtransactionStatus(pg_get_pgconn(self)));
}

/*
 * call-seq:
 *    conn.parameter_status( param_name ) -> String
 *
 * Returns the setting of parameter _param_name_, where
 * _param_name_ is one of
 * * +server_version+
 * * +server_encoding+
 * * +client_encoding+ 
 * * +is_superuser+
 * * +session_authorization+
 * * +DateStyle+
 * * +TimeZone+
 * * +integer_datetimes+
 * * +standard_conforming_strings+
 * 
 * Returns nil if the value of the parameter is not known.
 */
static VALUE
pgconn_parameter_status(VALUE self, VALUE param_name)
{
	const char *ret = PQparameterStatus(pg_get_pgconn(self), StringValuePtr(param_name));
	if(ret == NULL)
		return Qnil;
	else
		return rb_tainted_str_new2(ret);
}

/*
 * call-seq:
 *   conn.protocol_version -> Integer
 *
 * The 3.0 protocol will normally be used when communicating with PostgreSQL 7.4 
 * or later servers; pre-7.4 servers support only protocol 2.0. (Protocol 1.0 is 
 * obsolete and not supported by libpq.)
 */
static VALUE
pgconn_protocol_version(VALUE self)
{
	return INT2NUM(PQprotocolVersion(pg_get_pgconn(self)));
}

/* 
 * call-seq: 
 *   conn.server_version -> Integer
 * 
 * The number is formed by converting the major, minor, and revision
 * numbers into two-decimal-digit numbers and appending them together.
 * For example, version 7.4.2 will be returned as 70402, and version
 * 8.1 will be returned as 80100 (leading zeroes are not shown). Zero
 * is returned if the connection is bad.
 * 
 */
static VALUE
pgconn_server_version(VALUE self)
{
	return INT2NUM(PQserverVersion(pg_get_pgconn(self)));
}

/*
 * call-seq:
 *    conn.error_message -> String
 *
 * Returns the error message about connection.
 */
static VALUE
pgconn_error_message(VALUE self)
{
	char *error = PQerrorMessage(pg_get_pgconn(self));
	if (!error) return Qnil;
	return rb_tainted_str_new2(error);
}

/*
 * call-seq:
 *    conn.socket() -> Fixnum
 *
 * Returns the socket's file descriptor for this connection.
 */
static VALUE
pgconn_socket(VALUE self)
{
	int sd;
	if( (sd = PQsocket(pg_get_pgconn(self))) < 0)
		rb_raise(rb_ePGerror, "Can't get socket descriptor");
	return INT2NUM(sd);
}


/*
 * call-seq:
 *    conn.backend_pid() -> Fixnum
 *
 * Returns the process ID of the backend server
 * process for this connection.
 * Note that this is a PID on database server host.
 */
static VALUE
pgconn_backend_pid(VALUE self)
{
	return INT2NUM(PQbackendPID(pg_get_pgconn(self)));
}

/*
 * call-seq:
 *    conn.connection_needs_password() -> Boolean
 *
 * Returns +true+ if the authentication method required a
 * password, but none was available. +false+ otherwise.
 */
static VALUE
pgconn_connection_needs_password(VALUE self)
{
	return PQconnectionNeedsPassword(pg_get_pgconn(self)) ? Qtrue : Qfalse;
}

/*
 * call-seq:
 *    conn.connection_used_password() -> Boolean
 *
 * Returns +true+ if the authentication method used
 * a caller-supplied password, +false+ otherwise.
 */
static VALUE
pgconn_connection_used_password(VALUE self)
{
	return PQconnectionUsedPassword(pg_get_pgconn(self)) ? Qtrue : Qfalse;
}


/* :TODO: get_ssl */


/*
 * call-seq:
 *    conn.exec(sql [, params, result_format ] ) -> PGresult
 *    conn.exec(sql [, params, result_format ] ) {|pg_result| block }
 *
 * Sends SQL query request specified by _sql_ to PostgreSQL.
 * Returns a PGresult instance on success.
 * On failure, it raises a PGError exception.
 *
 * +params+ is an optional array of the bind parameters for the SQL query.
 * Each element of the +params+ array may be either:
 *   a hash of the form:
 *     {:value  => String (value of bind parameter)
 *      :type   => Fixnum (oid of type of bind parameter)
 *      :format => Fixnum (0 for text, 1 for binary)
 *     }
 *   or, it may be a String. If it is a string, that is equivalent to the hash:
 *     { :value => <string value>, :type => 0, :format => 0 }
 * 
 * PostgreSQL bind parameters are represented as $1, $1, $2, etc.,
 * inside the SQL query. The 0th element of the +params+ array is bound
 * to $1, the 1st element is bound to $2, etc. +nil+ is treated as +NULL+.
 * 
 * If the types are not specified, they will be inferred by PostgreSQL.
 * Instead of specifying type oids, it's recommended to simply add
 * explicit casts in the query to ensure that the right type is used.
 *
 * For example: "SELECT $1::int"
 *
 * The optional +result_format+ should be 0 for text results, 1
 * for binary.
 *
 * If the optional code block is given, it will be passed <i>result</i> as an argument, 
 * and the PGresult object will  automatically be cleared when the block terminates. 
 * In this instance, <code>conn.exec</code> returns the value of the block.
 */
static VALUE
pgconn_exec(int argc, VALUE *argv, VALUE self)
{
	PGconn *conn = pg_get_pgconn(self);
	PGresult *result = NULL;
	VALUE rb_pgresult;
	VALUE command, params, in_res_fmt;
	VALUE param, param_type, param_value, param_format;
	VALUE param_value_tmp;
	VALUE sym_type, sym_value, sym_format;
	VALUE gc_array;
	int i=0;
	int nParams;
	Oid *paramTypes;
	char ** paramValues;
	int *paramLengths;
	int *paramFormats;
	int resultFormat;

	rb_scan_args(argc, argv, "12", &command, &params, &in_res_fmt);

	Check_Type(command, T_STRING);

	/* If called with no parameters, use PQexec */
	if(NIL_P(params)) {
		result = PQexec(conn, StringValuePtr(command));
		rb_pgresult = pg_new_result(result, conn);
		pg_check_result(self, rb_pgresult);
		if (rb_block_given_p()) {
			return rb_ensure(rb_yield, rb_pgresult, pg_result_clear, rb_pgresult);
		}
		return rb_pgresult;
	}

	/* If called with parameters, and optionally result_format,
	 * use PQexecParams
	 */
	Check_Type(params, T_ARRAY);

	if(NIL_P(in_res_fmt)) {
		resultFormat = 0;
	}
	else {
		resultFormat = NUM2INT(in_res_fmt);
	}

	gc_array = rb_ary_new();
	rb_gc_register_address(&gc_array);
	sym_type = ID2SYM(rb_intern("type"));
	sym_value = ID2SYM(rb_intern("value"));
	sym_format = ID2SYM(rb_intern("format"));
	nParams = (int)RARRAY_LEN(params);
	paramTypes = ALLOC_N(Oid, nParams); 
	paramValues = ALLOC_N(char *, nParams);
	paramLengths = ALLOC_N(int, nParams);
	paramFormats = ALLOC_N(int, nParams);
	for(i = 0; i < nParams; i++) {
		param = rb_ary_entry(params, i);
		if (TYPE(param) == T_HASH) {
			param_type = rb_hash_aref(param, sym_type);
			param_value_tmp = rb_hash_aref(param, sym_value);
			if(param_value_tmp == Qnil)
				param_value = param_value_tmp;
			else
				param_value = rb_obj_as_string(param_value_tmp);
			param_format = rb_hash_aref(param, sym_format);
		}
		else {
			param_type = Qnil;
			if(param == Qnil)
				param_value = param;
			else
				param_value = rb_obj_as_string(param);
			param_format = Qnil;
		}

		if(param_type == Qnil)
			paramTypes[i] = 0;
		else
			paramTypes[i] = NUM2INT(param_type);

		if(param_value == Qnil) {
			paramValues[i] = NULL;
			paramLengths[i] = 0;
		}
		else {
			Check_Type(param_value, T_STRING);
			/* make sure param_value doesn't get freed by the GC */
			rb_ary_push(gc_array, param_value);
			paramValues[i] = StringValuePtr(param_value);
			paramLengths[i] = (int)RSTRING_LEN(param_value);
		}

		if(param_format == Qnil)
			paramFormats[i] = 0;
		else
			paramFormats[i] = NUM2INT(param_format);
	}

	result = PQexecParams(conn, StringValuePtr(command), nParams, paramTypes, 
		(const char * const *)paramValues, paramLengths, paramFormats, resultFormat);

	rb_gc_unregister_address(&gc_array);

	xfree(paramTypes);
	xfree(paramValues);
	xfree(paramLengths);
	xfree(paramFormats);

	rb_pgresult = pg_new_result(result, conn);
	pg_check_result(self, rb_pgresult);
	if (rb_block_given_p()) {
		return rb_ensure(rb_yield, rb_pgresult, 
			pg_result_clear, rb_pgresult);
	}
	return rb_pgresult;
}

/*
 * call-seq:
 *    conn.prepare(stmt_name, sql [, param_types ] ) -> PGresult
 *
 * Prepares statement _sql_ with name _name_ to be executed later.
 * Returns a PGresult instance on success.
 * On failure, it raises a PGError exception.
 *
 * +param_types+ is an optional parameter to specify the Oids of the 
 * types of the parameters.
 *
 * If the types are not specified, they will be inferred by PostgreSQL.
 * Instead of specifying type oids, it's recommended to simply add
 * explicit casts in the query to ensure that the right type is used.
 *
 * For example: "SELECT $1::int"
 * 
 * PostgreSQL bind parameters are represented as $1, $1, $2, etc.,
 * inside the SQL query.
 */
static VALUE
pgconn_prepare(int argc, VALUE *argv, VALUE self)
{
	PGconn *conn = pg_get_pgconn(self);
	PGresult *result = NULL;
	VALUE rb_pgresult;
	VALUE name, command, in_paramtypes;
	VALUE param;
	int i = 0;
	int nParams = 0;
	Oid *paramTypes = NULL;

	rb_scan_args(argc, argv, "21", &name, &command, &in_paramtypes);
	Check_Type(name, T_STRING);
	Check_Type(command, T_STRING);

	if(! NIL_P(in_paramtypes)) {
		Check_Type(in_paramtypes, T_ARRAY);
		nParams = (int)RARRAY_LEN(in_paramtypes);
		paramTypes = ALLOC_N(Oid, nParams); 
		for(i = 0; i < nParams; i++) {
			param = rb_ary_entry(in_paramtypes, i);
			Check_Type(param, T_FIXNUM);
			if(param == Qnil)
				paramTypes[i] = 0;
			else
				paramTypes[i] = NUM2INT(param);
		}
	}
	result = PQprepare(conn, StringValuePtr(name), StringValuePtr(command),
			nParams, paramTypes);

	xfree(paramTypes);

	rb_pgresult = pg_new_result(result, conn);
	pg_check_result(self, rb_pgresult);
	return rb_pgresult;
}

/*
 * call-seq:
 *    conn.exec_prepared(statement_name [, params, result_format ] ) -> PGresult
 *    conn.exec_prepared(statement_name [, params, result_format ] ) {|pg_result| block }
 *
 * Execute prepared named statement specified by _statement_name_.
 * Returns a PGresult instance on success.
 * On failure, it raises a PGError exception.
 *
 * +params+ is an array of the optional bind parameters for the 
 * SQL query. Each element of the +params+ array may be either:
 *   a hash of the form:
 *     {:value  => String (value of bind parameter)
 *      :format => Fixnum (0 for text, 1 for binary)
 *     }
 *   or, it may be a String. If it is a string, that is equivalent to the hash:
 *     { :value => <string value>, :format => 0 }
 * 
 * PostgreSQL bind parameters are represented as $1, $1, $2, etc.,
 * inside the SQL query. The 0th element of the +params+ array is bound
 * to $1, the 1st element is bound to $2, etc. +nil+ is treated as +NULL+.
 *
 * The optional +result_format+ should be 0 for text results, 1
 * for binary.
 *
 * If the optional code block is given, it will be passed <i>result</i> as an argument, 
 * and the PGresult object will  automatically be cleared when the block terminates. 
 * In this instance, <code>conn.exec_prepared</code> returns the value of the block.
 */
static VALUE
pgconn_exec_prepared(int argc, VALUE *argv, VALUE self)
{
	PGconn *conn = pg_get_pgconn(self);
	PGresult *result = NULL;
	VALUE rb_pgresult;
	VALUE name, params, in_res_fmt;
	VALUE param, param_value, param_format;
	VALUE param_value_tmp;
	VALUE sym_value, sym_format;
	VALUE gc_array;
	int i = 0;
	int nParams;
	char ** paramValues;
	int *paramLengths;
	int *paramFormats;
	int resultFormat;


	rb_scan_args(argc, argv, "12", &name, &params, &in_res_fmt);
	Check_Type(name, T_STRING);

	if(NIL_P(params)) {
		params = rb_ary_new2(0);
		resultFormat = 0;
	}
	else {
		Check_Type(params, T_ARRAY);
	}

	if(NIL_P(in_res_fmt)) {
		resultFormat = 0;
	}
	else {
		resultFormat = NUM2INT(in_res_fmt);
	}

	gc_array = rb_ary_new();
	rb_gc_register_address(&gc_array);
	sym_value = ID2SYM(rb_intern("value"));
	sym_format = ID2SYM(rb_intern("format"));
	nParams = (int)RARRAY_LEN(params);
	paramValues = ALLOC_N(char *, nParams);
	paramLengths = ALLOC_N(int, nParams);
	paramFormats = ALLOC_N(int, nParams);
	for(i = 0; i < nParams; i++) {
		param = rb_ary_entry(params, i);
		if (TYPE(param) == T_HASH) {
			param_value_tmp = rb_hash_aref(param, sym_value);
			if(param_value_tmp == Qnil)
				param_value = param_value_tmp;
			else
				param_value = rb_obj_as_string(param_value_tmp);
			param_format = rb_hash_aref(param, sym_format);
		}
		else {
			if(param == Qnil)
				param_value = param;
			else
				param_value = rb_obj_as_string(param);
			param_format = INT2NUM(0);
		}
		if(param_value == Qnil) {
			paramValues[i] = NULL;
			paramLengths[i] = 0;
		}
		else {
			Check_Type(param_value, T_STRING);
			/* make sure param_value doesn't get freed by the GC */
			rb_ary_push(gc_array, param_value);
			paramValues[i] = StringValuePtr(param_value);
			paramLengths[i] = (int)RSTRING_LEN(param_value);
		}

		if(param_format == Qnil)
			paramFormats[i] = 0;
		else
			paramFormats[i] = NUM2INT(param_format);
	}

	result = PQexecPrepared(conn, StringValuePtr(name), nParams, 
		(const char * const *)paramValues, paramLengths, paramFormats, 
		resultFormat);

	rb_gc_unregister_address(&gc_array);

	xfree(paramValues);
	xfree(paramLengths);
	xfree(paramFormats);

	rb_pgresult = pg_new_result(result, conn);
	pg_check_result(self, rb_pgresult);
	if (rb_block_given_p()) {
		return rb_ensure(rb_yield, rb_pgresult, 
			pg_result_clear, rb_pgresult);
	}
	return rb_pgresult;
}

/*
 * call-seq:
 *    conn.describe_prepared( statement_name ) -> PGresult
 *
 * Retrieve information about the prepared statement
 * _statement_name_.
 */
static VALUE
pgconn_describe_prepared(VALUE self, VALUE stmt_name)
{
	PGresult *result;
	VALUE rb_pgresult;
	PGconn *conn = pg_get_pgconn(self);
	char *stmt;
	if(stmt_name == Qnil) {
		stmt = NULL;
	}
	else {
		Check_Type(stmt_name, T_STRING);
		stmt = StringValuePtr(stmt_name);
	}
	result = PQdescribePrepared(conn, stmt);
	rb_pgresult = pg_new_result(result, conn);
	pg_check_result(self, rb_pgresult);
	return rb_pgresult;
}


/*
 * call-seq:
 *    conn.describe_portal( portal_name ) -> PGresult
 *
 * Retrieve information about the portal _portal_name_.
 */
static VALUE
pgconn_describe_portal(self, stmt_name)
	VALUE self, stmt_name;
{
	PGresult *result;
	VALUE rb_pgresult;
	PGconn *conn = pg_get_pgconn(self);
	char *stmt;
	if(stmt_name == Qnil) {
		stmt = NULL;
	}
	else {
		Check_Type(stmt_name, T_STRING);
		stmt = StringValuePtr(stmt_name);
	}
	result = PQdescribePortal(conn, stmt);
	rb_pgresult = pg_new_result(result, conn);
	pg_check_result(self, rb_pgresult);
	return rb_pgresult;
}


/*
 * call-seq:
 *    conn.make_empty_pgresult( status ) -> PGresult
 *
 * Constructs and empty PGresult with status _status_.
 * _status_ may be one of:
 * * +PGRES_EMPTY_QUERY+
 * * +PGRES_COMMAND_OK+
 * * +PGRES_TUPLES_OK+
 * * +PGRES_COPY_OUT+
 * * +PGRES_COPY_IN+
 * * +PGRES_BAD_RESPONSE+
 * * +PGRES_NONFATAL_ERROR+
 * * +PGRES_FATAL_ERROR+
 */
static VALUE
pgconn_make_empty_pgresult(VALUE self, VALUE status)
{
	PGresult *result;
	VALUE rb_pgresult;
	PGconn *conn = pg_get_pgconn(self);
	result = PQmakeEmptyPGresult(conn, NUM2INT(status));
	rb_pgresult = pg_new_result(result, conn);
	pg_check_result(self, rb_pgresult);
	return rb_pgresult;
}


/*
 * call-seq:
 *    conn.escape_string( str ) -> String
 *
 * Connection instance method for versions of 8.1 and higher of libpq
 * uses PQescapeStringConn, which is safer. Avoid calling as a class method,
 * the class method uses the deprecated PQescapeString() API function.
 * 
 * Returns a SQL-safe version of the String _str_.
 * This is the preferred way to make strings safe for inclusion in 
 * SQL queries.
 * 
 * Consider using exec_params, which avoids the need for passing values 
 * inside of SQL commands.
 *
 * Encoding of escaped string will be equal to client encoding of connection.
 */
static VALUE
pgconn_s_escape(VALUE self, VALUE string)
{
	char *escaped;
	size_t size;
	int error;
	VALUE result;
#ifdef M17N_SUPPORTED	
	rb_encoding* enc;
#endif

	Check_Type(string, T_STRING);

	escaped = ALLOC_N(char, RSTRING_LEN(string) * 2 + 1);
	if(rb_obj_class(self) == rb_cPGconn) {
		size = PQescapeStringConn(pg_get_pgconn(self), escaped, 
			RSTRING_PTR(string), RSTRING_LEN(string), &error);
		if(error) {
			xfree(escaped);
			rb_raise(rb_ePGerror, "%s", PQerrorMessage(pg_get_pgconn(self)));
		}
	} else {
		size = PQescapeString(escaped, RSTRING_PTR(string), (int)RSTRING_LEN(string));
	}
	result = rb_str_new(escaped, size);
	xfree(escaped);
	OBJ_INFECT(result, string);

#ifdef M17N_SUPPORTED
	if ( rb_obj_class(self) == rb_cPGconn ) {
		enc = pg_conn_enc_get( pg_get_pgconn(self) );
	} else {
		enc = rb_enc_get(string);
	}
	rb_enc_associate(result, enc);
#endif

	return result;
}

/*
 * call-seq:
 *   conn.escape_bytea( string ) -> String 
 *
 * Connection instance method for versions of 8.1 and higher of libpq
 * uses PQescapeByteaConn, which is safer. Avoid calling as a class method,
 * the class method uses the deprecated PQescapeBytea() API function.
 *
 * Use the instance method version of this function, it is safer than the
 * class method.
 *
 * Escapes binary data for use within an SQL command with the type +bytea+.
 * 
 * Certain byte values must be escaped (but all byte values may be escaped)
 * when used as part of a +bytea+ literal in an SQL statement. In general, to
 * escape a byte, it is converted into the three digit octal number equal to
 * the octet value, and preceded by two backslashes. The single quote (') and
 * backslash (\) characters have special alternative escape sequences.
 * #escape_bytea performs this operation, escaping only the minimally required 
 * bytes.
 * 
 * Consider using exec_params, which avoids the need for passing values inside of 
 * SQL commands.
 */
static VALUE
pgconn_s_escape_bytea(VALUE self, VALUE str)
{
	unsigned char *from, *to;
	size_t from_len, to_len;
	VALUE ret;

	Check_Type(str, T_STRING);
	from      = (unsigned char*)RSTRING_PTR(str);
	from_len  = RSTRING_LEN(str);

	if(rb_obj_class(self) == rb_cPGconn) {
		to = PQescapeByteaConn(pg_get_pgconn(self), from, from_len, &to_len);
	} else {
		to = PQescapeBytea( from, from_len, &to_len);
	}

	ret = rb_str_new((char*)to, to_len - 1);
	OBJ_INFECT(ret, str);
	PQfreemem(to);
	return ret;
}


/*
 * call-seq:
 *   PG::Connection.unescape_bytea( string )
 *
 * Converts an escaped string representation of binary data into binary data --- the
 * reverse of #escape_bytea. This is needed when retrieving +bytea+ data in text format,
 * but not when retrieving it in binary format.
 *
 */
static VALUE
pgconn_s_unescape_bytea(VALUE self, VALUE str)
{
	unsigned char *from, *to;
	size_t to_len;
	VALUE ret;

	UNUSED( self );

	Check_Type(str, T_STRING);
	from = (unsigned char*)StringValuePtr(str);

	to = PQunescapeBytea(from, &to_len);

	ret = rb_str_new((char*)to, to_len);
	OBJ_INFECT(ret, str);
	PQfreemem(to);
	return ret;
}

/*
 * call-seq:
 *    conn.send_query(sql [, params, result_format ] ) -> nil
 *
 * Sends SQL query request specified by _sql_ to PostgreSQL for
 * asynchronous processing, and immediately returns.
 * On failure, it raises a PGError exception.
 *
 * +params+ is an optional array of the bind parameters for the SQL query.
 * Each element of the +params+ array may be either:
 *   a hash of the form:
 *     {:value  => String (value of bind parameter)
 *      :type   => Fixnum (oid of type of bind parameter)
 *      :format => Fixnum (0 for text, 1 for binary)
 *     }
 *   or, it may be a String. If it is a string, that is equivalent to the hash:
 *     { :value => <string value>, :type => 0, :format => 0 }
 * 
 * PostgreSQL bind parameters are represented as $1, $1, $2, etc.,
 * inside the SQL query. The 0th element of the +params+ array is bound
 * to $1, the 1st element is bound to $2, etc. +nil+ is treated as +NULL+.
 * 
 * If the types are not specified, they will be inferred by PostgreSQL.
 * Instead of specifying type oids, it's recommended to simply add
 * explicit casts in the query to ensure that the right type is used.
 *
 * For example: "SELECT $1::int"
 *
 * The optional +result_format+ should be 0 for text results, 1
 * for binary.
 */
static VALUE
pgconn_send_query(int argc, VALUE *argv, VALUE self)
{
	PGconn *conn = pg_get_pgconn(self);
	int result;
	VALUE command, params, in_res_fmt;
	VALUE param, param_type, param_value, param_format;
	VALUE param_value_tmp;
	VALUE sym_type, sym_value, sym_format;
	VALUE gc_array;
	VALUE error;
	int i=0;
	int nParams;
	Oid *paramTypes;
	char ** paramValues;
	int *paramLengths;
	int *paramFormats;
	int resultFormat;

	rb_scan_args(argc, argv, "12", &command, &params, &in_res_fmt);
	Check_Type(command, T_STRING);

	/* If called with no parameters, use PQsendQuery */
	if(NIL_P(params)) {
		if(PQsendQuery(conn,StringValuePtr(command)) == 0) {
			error = rb_exc_new2(rb_ePGerror, PQerrorMessage(conn));
			rb_iv_set(error, "@connection", self);
			rb_exc_raise(error);
		}
		return Qnil;
	}

	/* If called with parameters, and optionally result_format,
	 * use PQsendQueryParams
	 */
	Check_Type(params, T_ARRAY);

	if(NIL_P(in_res_fmt)) {
		resultFormat = 0;
	}
	else {
		resultFormat = NUM2INT(in_res_fmt);
	}

	gc_array = rb_ary_new();
	rb_gc_register_address(&gc_array);
	sym_type = ID2SYM(rb_intern("type"));
	sym_value = ID2SYM(rb_intern("value"));
	sym_format = ID2SYM(rb_intern("format"));
	nParams = (int)RARRAY_LEN(params);
	paramTypes = ALLOC_N(Oid, nParams); 
	paramValues = ALLOC_N(char *, nParams);
	paramLengths = ALLOC_N(int, nParams);
	paramFormats = ALLOC_N(int, nParams);
	for(i = 0; i < nParams; i++) {
		param = rb_ary_entry(params, i);
		if (TYPE(param) == T_HASH) {
			param_type = rb_hash_aref(param, sym_type);
			param_value_tmp = rb_hash_aref(param, sym_value);
			if(param_value_tmp == Qnil)
				param_value = param_value_tmp;
			else
				param_value = rb_obj_as_string(param_value_tmp);
			param_format = rb_hash_aref(param, sym_format);
		}
		else {
			param_type = INT2NUM(0);
			if(param == Qnil)
				param_value = param;
			else
				param_value = rb_obj_as_string(param);
			param_format = INT2NUM(0);
		}

		if(param_type == Qnil)
			paramTypes[i] = 0;
		else
			paramTypes[i] = NUM2INT(param_type);

		if(param_value == Qnil) {
			paramValues[i] = NULL;
			paramLengths[i] = 0;
		}
		else {
			Check_Type(param_value, T_STRING);
			/* make sure param_value doesn't get freed by the GC */
			rb_ary_push(gc_array, param_value);
			paramValues[i] = StringValuePtr(param_value);
			paramLengths[i] = (int)RSTRING_LEN(param_value);
		}

		if(param_format == Qnil)
			paramFormats[i] = 0;
		else
			paramFormats[i] = NUM2INT(param_format);
	}

	result = PQsendQueryParams(conn, StringValuePtr(command), nParams, paramTypes, 
		(const char * const *)paramValues, paramLengths, paramFormats, resultFormat);

	rb_gc_unregister_address(&gc_array);	

	xfree(paramTypes);
	xfree(paramValues);
	xfree(paramLengths);
	xfree(paramFormats);

	if(result == 0) {
		error = rb_exc_new2(rb_ePGerror, PQerrorMessage(conn));
		rb_iv_set(error, "@connection", self);
		rb_exc_raise(error);
	}
	return Qnil;
}

/*
 * call-seq:
 *    conn.send_prepare( stmt_name, sql [, param_types ] ) -> nil
 *
 * Prepares statement _sql_ with name _name_ to be executed later.
 * Sends prepare command asynchronously, and returns immediately.
 * On failure, it raises a PGError exception.
 *
 * +param_types+ is an optional parameter to specify the Oids of the 
 * types of the parameters.
 *
 * If the types are not specified, they will be inferred by PostgreSQL.
 * Instead of specifying type oids, it's recommended to simply add
 * explicit casts in the query to ensure that the right type is used.
 *
 * For example: "SELECT $1::int"
 * 
 * PostgreSQL bind parameters are represented as $1, $1, $2, etc.,
 * inside the SQL query.
 */
static VALUE
pgconn_send_prepare(int argc, VALUE *argv, VALUE self)
{
	PGconn *conn = pg_get_pgconn(self);
	int result;
	VALUE name, command, in_paramtypes;
	VALUE param;
	VALUE error;
	int i = 0;
	int nParams = 0;
	Oid *paramTypes = NULL;

	rb_scan_args(argc, argv, "21", &name, &command, &in_paramtypes);
	Check_Type(name, T_STRING);
	Check_Type(command, T_STRING);

	if(! NIL_P(in_paramtypes)) {
		Check_Type(in_paramtypes, T_ARRAY);
		nParams = (int)RARRAY_LEN(in_paramtypes);
		paramTypes = ALLOC_N(Oid, nParams); 
		for(i = 0; i < nParams; i++) {
			param = rb_ary_entry(in_paramtypes, i);
			Check_Type(param, T_FIXNUM);
			if(param == Qnil)
				paramTypes[i] = 0;
			else
				paramTypes[i] = NUM2INT(param);
		}
	}
	result = PQsendPrepare(conn, StringValuePtr(name), StringValuePtr(command),
			nParams, paramTypes);

	xfree(paramTypes);

	if(result == 0) {
		error = rb_exc_new2(rb_ePGerror, PQerrorMessage(conn));
		rb_iv_set(error, "@connection", self);
		rb_exc_raise(error);
	}
	return Qnil;
}

/*
 * call-seq:
 *    conn.send_query_prepared( statement_name [, params, result_format ] )
 *      -> nil
 *
 * Execute prepared named statement specified by _statement_name_
 * asynchronously, and returns immediately.
 * On failure, it raises a PGError exception.
 *
 * +params+ is an array of the optional bind parameters for the 
 * SQL query. Each element of the +params+ array may be either:
 *   a hash of the form:
 *     {:value  => String (value of bind parameter)
 *      :format => Fixnum (0 for text, 1 for binary)
 *     }
 *   or, it may be a String. If it is a string, that is equivalent to the hash:
 *     { :value => <string value>, :format => 0 }
 * 
 * PostgreSQL bind parameters are represented as $1, $1, $2, etc.,
 * inside the SQL query. The 0th element of the +params+ array is bound
 * to $1, the 1st element is bound to $2, etc. +nil+ is treated as +NULL+.
 *
 * The optional +result_format+ should be 0 for text results, 1
 * for binary.
 */
static VALUE
pgconn_send_query_prepared(int argc, VALUE *argv, VALUE self)
{
	PGconn *conn = pg_get_pgconn(self);
	int result;
	VALUE name, params, in_res_fmt;
	VALUE param, param_value, param_format;
	VALUE param_value_tmp;
	VALUE sym_value, sym_format;
	VALUE gc_array;
	VALUE error;
	int i = 0;
	int nParams;
	char ** paramValues;
	int *paramLengths;
	int *paramFormats;
	int resultFormat;

	rb_scan_args(argc, argv, "12", &name, &params, &in_res_fmt);
	Check_Type(name, T_STRING);

	if(NIL_P(params)) {
		params = rb_ary_new2(0);
		resultFormat = 0;
	}
	else {
		Check_Type(params, T_ARRAY);
	}

	if(NIL_P(in_res_fmt)) {
		resultFormat = 0;
	}
	else {
		resultFormat = NUM2INT(in_res_fmt);
	}

	gc_array = rb_ary_new();
	rb_gc_register_address(&gc_array);
	sym_value = ID2SYM(rb_intern("value"));
	sym_format = ID2SYM(rb_intern("format"));
	nParams = (int)RARRAY_LEN(params);
	paramValues = ALLOC_N(char *, nParams);
	paramLengths = ALLOC_N(int, nParams);
	paramFormats = ALLOC_N(int, nParams);
	for(i = 0; i < nParams; i++) {
		param = rb_ary_entry(params, i);
		if (TYPE(param) == T_HASH) {
			param_value_tmp = rb_hash_aref(param, sym_value);
			if(param_value_tmp == Qnil)
				param_value = param_value_tmp;
			else
				param_value = rb_obj_as_string(param_value_tmp);
			param_format = rb_hash_aref(param, sym_format);
		}
		else {
			if(param == Qnil)
				param_value = param;
			else
				param_value = rb_obj_as_string(param);
			param_format = INT2NUM(0);
		}

		if(param_value == Qnil) {
			paramValues[i] = NULL;
			paramLengths[i] = 0;
		}
		else {
			Check_Type(param_value, T_STRING);
			/* make sure param_value doesn't get freed by the GC */
			rb_ary_push(gc_array, param_value);
			paramValues[i] = StringValuePtr(param_value);
			paramLengths[i] = (int)RSTRING_LEN(param_value);
		}

		if(param_format == Qnil)
			paramFormats[i] = 0;
		else
			paramFormats[i] = NUM2INT(param_format);
	}

	result = PQsendQueryPrepared(conn, StringValuePtr(name), nParams, 
		(const char * const *)paramValues, paramLengths, paramFormats, 
		resultFormat);

	rb_gc_unregister_address(&gc_array);

	xfree(paramValues);
	xfree(paramLengths);
	xfree(paramFormats);

	if(result == 0) {
		error = rb_exc_new2(rb_ePGerror, PQerrorMessage(conn));
		rb_iv_set(error, "@connection", self);
		rb_exc_raise(error);
	}
	return Qnil;
}

/*
 * call-seq:
 *    conn.send_describe_prepared( statement_name ) -> nil
 *
 * Asynchronously send _command_ to the server. Does not block. 
 * Use in combination with +conn.get_result+.
 */
static VALUE
pgconn_send_describe_prepared(VALUE self, VALUE stmt_name)
{
	VALUE error;
	PGconn *conn = pg_get_pgconn(self);
	/* returns 0 on failure */
	if(PQsendDescribePrepared(conn,StringValuePtr(stmt_name)) == 0) {
		error = rb_exc_new2(rb_ePGerror, PQerrorMessage(conn));
		rb_iv_set(error, "@connection", self);
		rb_exc_raise(error);
	}
	return Qnil;
}


/*
 * call-seq:
 *    conn.send_describe_portal( portal_name ) -> nil
 *
 * Asynchronously send _command_ to the server. Does not block. 
 * Use in combination with +conn.get_result+.
 */
static VALUE
pgconn_send_describe_portal(VALUE self, VALUE portal)
{
	VALUE error;
	PGconn *conn = pg_get_pgconn(self);
	/* returns 0 on failure */
	if(PQsendDescribePortal(conn,StringValuePtr(portal)) == 0) {
		error = rb_exc_new2(rb_ePGerror, PQerrorMessage(conn));
		rb_iv_set(error, "@connection", self);
		rb_exc_raise(error);
	}
	return Qnil;
}


/*
 * call-seq:
 *    conn.get_result() -> PGresult
 *    conn.get_result() {|pg_result| block }
 *
 * Blocks waiting for the next result from a call to
 * #send_query (or another asynchronous command), and returns
 * it. Returns +nil+ if no more results are available.
 *
 * Note: call this function repeatedly until it returns +nil+, or else
 * you will not be able to issue further commands.
 *
 * If the optional code block is given, it will be passed <i>result</i> as an argument, 
 * and the PGresult object will  automatically be cleared when the block terminates. 
 * In this instance, <code>conn.exec</code> returns the value of the block.
 */
static VALUE
pgconn_get_result(VALUE self)
{
	PGconn *conn = pg_get_pgconn(self);
	PGresult *result;
	VALUE rb_pgresult;

	result = PQgetResult(conn);
	if(result == NULL)
		return Qnil;
	rb_pgresult = pg_new_result(result, conn);
	if (rb_block_given_p()) {
		return rb_ensure(rb_yield, rb_pgresult,
			pg_result_clear, rb_pgresult);
	}
	return rb_pgresult;
}

/*
 * call-seq:
 *    conn.consume_input()
 *
 * If input is available from the server, consume it.
 * After calling +consume_input+, you can check +is_busy+
 * or *notifies* to see if the state has changed.
 */
static VALUE
pgconn_consume_input(self)
	VALUE self;
{
	VALUE error;
	PGconn *conn = pg_get_pgconn(self);
	/* returns 0 on error */
	if(PQconsumeInput(conn) == 0) {
		error = rb_exc_new2(rb_ePGerror, PQerrorMessage(conn));
		rb_iv_set(error, "@connection", self);
		rb_exc_raise(error);
	}
	return Qnil;
}

/*
 * call-seq:
 *    conn.is_busy() -> Boolean
 *
 * Returns +true+ if a command is busy, that is, if
 * PQgetResult would block. Otherwise returns +false+.
 */
static VALUE
pgconn_is_busy(self)
	VALUE self;
{
	return PQisBusy(pg_get_pgconn(self)) ? Qtrue : Qfalse;
}

/*
 * call-seq:
 *    conn.setnonblocking(Boolean) -> nil
 *
 * Sets the nonblocking status of the connection. 
 * In the blocking state, calls to #send_query
 * will block until the message is sent to the server,
 * but will not wait for the query results.
 * In the nonblocking state, calls to #send_query
 * will return an error if the socket is not ready for
 * writing.
 * Note: This function does not affect #exec, because
 * that function doesn't return until the server has 
 * processed the query and returned the results.
 * Returns +nil+.
 */
static VALUE
pgconn_setnonblocking(self, state)
	VALUE self, state;
{
	int arg;
	VALUE error;
	PGconn *conn = pg_get_pgconn(self);
	if(state == Qtrue)
		arg = 1;
	else if (state == Qfalse)
		arg = 0;
	else
		rb_raise(rb_eArgError, "Boolean value expected");

	if(PQsetnonblocking(conn, arg) == -1) {
		error = rb_exc_new2(rb_ePGerror, PQerrorMessage(conn));
		rb_iv_set(error, "@connection", self);
		rb_exc_raise(error);
	}
	return Qnil;
}


/*
 * call-seq:
 *    conn.isnonblocking() -> Boolean
 *
 * Returns +true+ if a command is busy, that is, if
 * PQgetResult would block. Otherwise returns +false+.
 */
static VALUE
pgconn_isnonblocking(self)
	VALUE self;
{
	return PQisnonblocking(pg_get_pgconn(self)) ? Qtrue : Qfalse;
}

/*
 * call-seq:
 *    conn.flush() -> Boolean
 *
 * Attempts to flush any queued output data to the server.
 * Returns +true+ if data is successfully flushed, +false+
 * if not (can only return +false+ if connection is
 * nonblocking.
 * Raises PGError exception if some other failure occurred.
 */
static VALUE
pgconn_flush(self)
	VALUE self;
{
	PGconn *conn = pg_get_pgconn(self);
	int ret;
	VALUE error;
	ret = PQflush(conn);
	if(ret == -1) {
		error = rb_exc_new2(rb_ePGerror, PQerrorMessage(conn));
		rb_iv_set(error, "@connection", self);
		rb_exc_raise(error);
	}
	return (ret) ? Qfalse : Qtrue;
}

/*
 * call-seq:
 *    conn.cancel() -> String
 *
 * Requests cancellation of the command currently being
 * processed. (Only implemented in PostgreSQL >= 8.0)
 *
 * Returns +nil+ on success, or a string containing the
 * error message if a failure occurs.
 */
static VALUE
pgconn_cancel(VALUE self)
{
#ifdef HAVE_PQGETCANCEL
	char errbuf[256];
	PGcancel *cancel;
	VALUE retval;
	int ret;

	cancel = PQgetCancel(pg_get_pgconn(self));
	if(cancel == NULL)
		rb_raise(rb_ePGerror,"Invalid connection!");

	ret = PQcancel(cancel, errbuf, 256);
	if(ret == 1)
		retval = Qnil;
	else
		retval = rb_str_new2(errbuf);

	PQfreeCancel(cancel);
	return retval;
#else
	rb_notimplement();
#endif
}


/*
 * call-seq:
 *    conn.notifies()
 *
 * Returns a hash of the unprocessed notifications.
 * If there is no unprocessed notifier, it returns +nil+.
 */
static VALUE
pgconn_notifies(VALUE self)
{
	PGconn* conn = pg_get_pgconn(self);
	PGnotify *notification;
	VALUE hash;
	VALUE sym_relname, sym_be_pid, sym_extra;
	VALUE relname, be_pid, extra;

	sym_relname = ID2SYM(rb_intern("relname"));
	sym_be_pid = ID2SYM(rb_intern("be_pid"));
	sym_extra = ID2SYM(rb_intern("extra"));

	notification = PQnotifies(conn);
	if (notification == NULL) {
		return Qnil;
	}

	hash = rb_hash_new();
	relname = rb_tainted_str_new2(notification->relname);
	be_pid = INT2NUM(notification->be_pid);
	extra = rb_tainted_str_new2(notification->extra);

	rb_hash_aset(hash, sym_relname, relname);
	rb_hash_aset(hash, sym_be_pid, be_pid);
	rb_hash_aset(hash, sym_extra, extra);

	PQfreemem(notification);
	return hash;
}


#ifdef _WIN32
/* 
 * Duplicate the sockets from libpq and create temporary CRT FDs
 */
void create_crt_fd(fd_set *os_set, fd_set *crt_set)
{
	int i;
	crt_set->fd_count = os_set->fd_count;
	for (i = 0; i < os_set->fd_count; i++) {
		WSAPROTOCOL_INFO wsa_pi;
		/* dupicate the SOCKET */
		int r = WSADuplicateSocket(os_set->fd_array[i], GetCurrentProcessId(), &wsa_pi);
		SOCKET s = WSASocket(wsa_pi.iAddressFamily, wsa_pi.iSocketType, wsa_pi.iProtocol, &wsa_pi, 0, 0);
		/* create the CRT fd so ruby can get back to the SOCKET */
		int fd = _open_osfhandle(s, O_RDWR|O_BINARY);
		os_set->fd_array[i] = s;
		crt_set->fd_array[i] = fd;
	}
}

/*
 * Clean up the CRT FDs from create_crt_fd()
 */
void cleanup_crt_fd(fd_set *os_set, fd_set *crt_set)
{
	int i;
	for (i = 0; i < os_set->fd_count; i++) {
		/* cleanup the CRT fd */
		_close(crt_set->fd_array[i]);
		/* cleanup the duplicated SOCKET */
		closesocket(os_set->fd_array[i]);
	}
}
#endif

/*
 * call-seq:
 *    conn.wait_for_notify( [ timeout ] ) -> String
 *    conn.wait_for_notify( [ timeout ] ) { |event, pid| block }
 *    conn.wait_for_notify( [ timeout ] ) { |event, pid, payload| block } # PostgreSQL 9.0
 *
 * Blocks while waiting for notification(s), or until the optional
 * _timeout_ is reached, whichever comes first.  _timeout_ is
 * measured in seconds and can be fractional.
 *
 * Returns +nil+ if _timeout_ is reached, the name of the NOTIFY
 * event otherwise.  If used in block form, passes the name of the
 * NOTIFY +event+ and the generating +pid+ into the block.
 * 
 * Under PostgreSQL 9.0 and later, if the notification is sent with
 * the optional +payload+ string, it will be given to the block as the
 * third argument.
 * 
 */
static VALUE
pgconn_wait_for_notify(int argc, VALUE *argv, VALUE self)
{
	PGconn *conn = pg_get_pgconn( self );
	PGnotify *notification;
	int sd = PQsocket( conn );
	int ret;
	struct timeval timeout;
	struct timeval *ptimeout = NULL;
	VALUE timeout_in = Qnil, relname = Qnil, be_pid = Qnil, extra = Qnil;
	double timeout_sec;
	fd_set sd_rset;
#ifdef _WIN32
	fd_set crt_sd_rset;
#endif

	if ( sd < 0 )
		rb_bug( "PQsocket(conn): couldn't fetch the connection's socket!" );

	rb_scan_args( argc, argv, "01", &timeout_in );

	if ( RTEST(timeout_in) ) {
		timeout_sec = NUM2DBL( timeout_in );
		timeout.tv_sec = (time_t)timeout_sec;
		timeout.tv_usec = (suseconds_t)( (timeout_sec - (long)timeout_sec) * 1e6 );
		ptimeout = &timeout;
	}

	/* Check for notifications */
	while ( (notification = PQnotifies(conn)) == NULL ) {
		FD_ZERO( &sd_rset );
		FD_SET( sd, &sd_rset );

#ifdef _WIN32
		create_crt_fd(&sd_rset, &crt_sd_rset);
#endif

		/* Wait for the socket to become readable before checking again */
		ret = rb_thread_select( sd+1, &sd_rset, NULL, NULL, ptimeout );

#ifdef _WIN32
		cleanup_crt_fd(&sd_rset, &crt_sd_rset);
#endif

		if ( ret < 0 )
			rb_sys_fail( 0 );

		/* Return nil if the select timed out */
		if ( ret == 0 ) return Qnil;

		/* Read the socket */
		if ( (ret = PQconsumeInput(conn)) != 1 )
			rb_raise( rb_ePGerror, "PQconsumeInput == %d: %s", ret, PQerrorMessage(conn) );
	}

	relname = rb_tainted_str_new2( notification->relname );
	ASSOCIATE_INDEX( relname, self );
	be_pid = INT2NUM( notification->be_pid );
#ifdef HAVE_ST_NOTIFY_EXTRA
	if ( *notification->extra ) {
		extra = rb_tainted_str_new2( notification->extra );
		ASSOCIATE_INDEX( extra, self );
	}
#endif
	PQfreemem( notification );

	if ( rb_block_given_p() )
		rb_yield_values( 3, relname, be_pid, extra );

	return relname;
}


/*
 * call-seq:
 *    conn.put_copy_data( buffer ) -> Boolean
 *
 * Transmits _buffer_ as copy data to the server.
 * Returns true if the data was sent, false if it was
 * not sent (false is only possible if the connection
 * is in nonblocking mode, and this command would block).
 *
 * Raises an exception if an error occurs.
 */
static VALUE
pgconn_put_copy_data(self, buffer)
	VALUE self, buffer;
{
	int ret;
	VALUE error;
	PGconn *conn = pg_get_pgconn(self);
	Check_Type(buffer, T_STRING);

	ret = PQputCopyData(conn, RSTRING_PTR(buffer), (int)RSTRING_LEN(buffer));
	if(ret == -1) {
		error = rb_exc_new2(rb_ePGerror, PQerrorMessage(conn));
		rb_iv_set(error, "@connection", self);
		rb_exc_raise(error);
	}
	return (ret) ? Qtrue : Qfalse;
}

/*
 * call-seq:
 *    conn.put_copy_end( [ error_message ] ) -> Boolean
 *
 * Sends end-of-data indication to the server.
 *
 * _error_message_ is an optional parameter, and if set,
 * forces the COPY command to fail with the string
 * _error_message_.
 *
 * Returns true if the end-of-data was sent, false if it was
 * not sent (false is only possible if the connection
 * is in nonblocking mode, and this command would block).
 */ 
static VALUE
pgconn_put_copy_end(int argc, VALUE *argv, VALUE self)
{
	VALUE str;
	VALUE error;
	int ret;
	char *error_message = NULL;
	PGconn *conn = pg_get_pgconn(self);

	if (rb_scan_args(argc, argv, "01", &str) == 0)
		error_message = NULL;
	else
		error_message = StringValuePtr(str);

	ret = PQputCopyEnd(conn, error_message);
	if(ret == -1) {
		error = rb_exc_new2(rb_ePGerror, PQerrorMessage(conn));
		rb_iv_set(error, "@connection", self);
		rb_exc_raise(error);
	}
	return (ret) ? Qtrue : Qfalse;
}

/*
 * call-seq:
 *    conn.get_copy_data( [ async = false ] ) -> String
 *
 * Return a string containing one row of data, +nil+
 * if the copy is done, or +false+ if the call would 
 * block (only possible if _async_ is true).
 *
 */
static VALUE
pgconn_get_copy_data(int argc, VALUE *argv, VALUE self )
{
	VALUE async_in;
	VALUE error;
	VALUE result_str;
	int ret;
	int async;
	char *buffer;
	PGconn *conn = pg_get_pgconn(self);

	if (rb_scan_args(argc, argv, "01", &async_in) == 0)
		async = 0;
	else
		async = (async_in == Qfalse || async_in == Qnil) ? 0 : 1;

	ret = PQgetCopyData(conn, &buffer, async);
	if(ret == -2) { /* error */
		error = rb_exc_new2(rb_ePGerror, PQerrorMessage(conn));
		rb_iv_set(error, "@connection", self);
		rb_exc_raise(error);
	}
	if(ret == -1) { /* No data left */
		return Qnil;
	}
	if(ret == 0) { /* would block */
		return Qfalse;
	}
	result_str = rb_tainted_str_new(buffer, ret);
	PQfreemem(buffer);
	return result_str;
}

/*
 * call-seq:
 *    conn.set_error_verbosity( verbosity ) -> Fixnum
 *
 * Sets connection's verbosity to _verbosity_ and returns
 * the previous setting. Available settings are:
 * * PQERRORS_TERSE
 * * PQERRORS_DEFAULT
 * * PQERRORS_VERBOSE
 */
static VALUE
pgconn_set_error_verbosity(VALUE self, VALUE in_verbosity)
{
	PGconn *conn = pg_get_pgconn(self);
	PGVerbosity verbosity = NUM2INT(in_verbosity);
	return INT2FIX(PQsetErrorVerbosity(conn, verbosity));
}

/*
 * call-seq:
 *    conn.trace( stream ) -> nil
 * 
 * Enables tracing message passing between backend. The 
 * trace message will be written to the stream _stream_,
 * which must implement a method +fileno+ that returns
 * a writable file descriptor.
 */
static VALUE
pgconn_trace(VALUE self, VALUE stream)
{
	VALUE fileno;
	FILE *new_fp;
	int old_fd, new_fd;
	VALUE new_file;

	if(rb_respond_to(stream,rb_intern("fileno")) == Qfalse)
		rb_raise(rb_eArgError, "stream does not respond to method: fileno");

	fileno = rb_funcall(stream, rb_intern("fileno"), 0);
	if(fileno == Qnil)
		rb_raise(rb_eArgError, "can't get file descriptor from stream");

	/* Duplicate the file descriptor and re-open
	 * it. Then, make it into a ruby File object
	 * and assign it to an instance variable.
	 * This prevents a problem when the File
	 * object passed to this function is closed
	 * before the connection object is. */
	old_fd = NUM2INT(fileno);
	new_fd = dup(old_fd);
	new_fp = fdopen(new_fd, "w");

	if(new_fp == NULL)
		rb_raise(rb_eArgError, "stream is not writable");

	new_file = rb_funcall(rb_cIO, rb_intern("new"), 1, INT2NUM(new_fd));
	rb_iv_set(self, "@trace_stream", new_file);

	PQtrace(pg_get_pgconn(self), new_fp);
	return Qnil;
}

/*
 * call-seq:
 *    conn.untrace() -> nil
 * 
 * Disables the message tracing.
 */
static VALUE
pgconn_untrace(VALUE self)
{
	VALUE trace_stream;
	PQuntrace(pg_get_pgconn(self));
	trace_stream = rb_iv_get(self, "@trace_stream");
	rb_funcall(trace_stream, rb_intern("close"), 0);
	rb_iv_set(self, "@trace_stream", Qnil);
	return Qnil;
}


/*
 * Notice callback proxy function -- delegate the callback to the
 * currently-registered Ruby notice_receiver object.
 */
static void
notice_receiver_proxy(void *arg, const PGresult *result)
{
	VALUE proc;
	VALUE self = (VALUE)arg;

	if ((proc = rb_iv_get(self, "@notice_receiver")) != Qnil) {
		rb_funcall(proc, rb_intern("call"), 1, 
			Data_Wrap_Struct(rb_cPGresult, NULL, NULL, (PGresult*)result));
	}
	return;
}

/*
 * call-seq:
 *   conn.set_notice_receiver {|result| ... } -> Proc
 *
 * Notice and warning messages generated by the server are not returned
 * by the query execution functions, since they do not imply failure of
 * the query. Instead they are passed to a notice handling function, and
 * execution continues normally after the handler returns. The default
 * notice handling function prints the message on <tt>stderr</tt>, but the
 * application can override this behavior by supplying its own handling
 * function.
 *
 * For historical reasons, there are two levels of notice handling, called the 
 * notice receiver and notice processor. The default behavior is for the notice 
 * receiver to format the notice and pass a string to the notice processor for 
 * printing. However, an application that chooses to provide its own notice 
 * receiver will typically ignore the notice processor layer and just do all 
 * the work in the notice receiver.
 *
 * This function takes a new block to act as the handler, which should
 * accept a single parameter that will be a PGresult object, and returns 
 * the Proc object previously set, or +nil+ if it was previously the default.
 *
 * If you pass no arguments, it will reset the handler to the default.
 */
static VALUE
pgconn_set_notice_receiver(VALUE self)
{
	VALUE proc, old_proc;
	PGconn *conn = pg_get_pgconn(self);

	/* If default_notice_receiver is unset, assume that the current 
	 * notice receiver is the default, and save it to a global variable. 
	 * This should not be a problem because the default receiver is
	 * always the same, so won't vary among connections.
	 */
	if(default_notice_receiver == NULL)
		default_notice_receiver = PQsetNoticeReceiver(conn, NULL, NULL);

	old_proc = rb_iv_get(self, "@notice_receiver");
	if( rb_block_given_p() ) {
		proc = rb_block_proc();
		PQsetNoticeReceiver(conn, notice_receiver_proxy, (void *)self);
	} else {
		/* if no block is given, set back to default */
		proc = Qnil;
		PQsetNoticeReceiver(conn, default_notice_receiver, NULL);
	}

	rb_iv_set(self, "@notice_receiver", proc);
	return old_proc;
}


/*
 * Notice callback proxy function -- delegate the callback to the
 * currently-registered Ruby notice_processor object.
 */
static void
notice_processor_proxy(void *arg, const char *message)
{
	VALUE proc;
	VALUE self = (VALUE)arg;

	if ((proc = rb_iv_get(self, "@notice_processor")) != Qnil) {
		rb_funcall(proc, rb_intern("call"), 1, rb_tainted_str_new2(message));
	}
	return;
}

/*
 * call-seq:
 *   conn.set_notice_processor {|message| ... } -> Proc
 *
 * See #set_notice_receiver for the desription of what this and the
 * notice_processor methods do.
 *
 * This function takes a new block to act as the notice processor and returns 
 * the Proc object previously set, or +nil+ if it was previously the default.
 * The block should accept a single PG::Result object.
 *
 * If you pass no arguments, it will reset the handler to the default.
 */
static VALUE
pgconn_set_notice_processor(VALUE self)
{
	VALUE proc, old_proc;
	PGconn *conn = pg_get_pgconn(self);

	/* If default_notice_processor is unset, assume that the current 
	 * notice processor is the default, and save it to a global variable. 
	 * This should not be a problem because the default processor is
	 * always the same, so won't vary among connections.
	 */
	if(default_notice_processor == NULL)
		default_notice_processor = PQsetNoticeProcessor(conn, NULL, NULL);

	old_proc = rb_iv_get(self, "@notice_processor");
	if( rb_block_given_p() ) {
		proc = rb_block_proc();
		PQsetNoticeProcessor(conn, notice_processor_proxy, (void *)self);
	} else {
		/* if no block is given, set back to default */
		proc = Qnil;
		PQsetNoticeProcessor(conn, default_notice_processor, NULL);
	}

	rb_iv_set(self, "@notice_processor", proc);
	return old_proc;
}


/*
 * call-seq:
 *    conn.get_client_encoding() -> String
 * 
 * Returns the client encoding as a String.
 */
static VALUE
pgconn_get_client_encoding(VALUE self)
{
	char *encoding = (char *)pg_encoding_to_char(PQclientEncoding(pg_get_pgconn(self)));
	return rb_tainted_str_new2(encoding);
}


/*
 * call-seq:
 *    conn.set_client_encoding( encoding )
 * 
 * Sets the client encoding to the _encoding_ String.
 */
static VALUE
pgconn_set_client_encoding(VALUE self, VALUE str)
{
	PGconn *conn = pg_get_pgconn( self );

	Check_Type(str, T_STRING);

	if ( (PQsetClientEncoding(conn, StringValuePtr(str))) == -1 ) {
		rb_raise(rb_ePGerror, "invalid encoding name: %s",StringValuePtr(str));
	}

	return Qnil;
}

/*
 * call-seq:
 *    conn.transaction { |conn| ... } -> nil
 *
 * Executes a +BEGIN+ at the start of the block,
 * and a +COMMIT+ at the end of the block, or 
 * +ROLLBACK+ if any exception occurs.
 */
static VALUE
pgconn_transaction(VALUE self)
{
	PGconn *conn = pg_get_pgconn(self);
	PGresult *result;
	VALUE rb_pgresult;
	int status;

	if (rb_block_given_p()) {
		result = PQexec(conn, "BEGIN");
		rb_pgresult = pg_new_result(result, conn);
		pg_check_result(self, rb_pgresult);
		rb_protect(rb_yield, self, &status);
		if(status == 0) {
			result = PQexec(conn, "COMMIT");
			rb_pgresult = pg_new_result(result, conn);
			pg_check_result(self, rb_pgresult);
		}
		else {
			/* exception occurred, ROLLBACK and re-raise */
			result = PQexec(conn, "ROLLBACK");
			rb_pgresult = pg_new_result(result, conn);
			pg_check_result(self, rb_pgresult);
			rb_jump_tag(status);
		}

	}
	else {
		/* no block supplied? */
		rb_raise(rb_eArgError, "Must supply block for PG::Connection#transaction");
	}
	return Qnil;
}


/*
 * call-seq:
 *    PG::Connection.quote_ident( str ) -> String
 *    conn.quote_ident( str ) -> String
 *
 * Returns a string that is safe for inclusion in a SQL query as an
 * identifier. Note: this is not a quote function for values, but for
 * identifiers.
 * 
 * For example, in a typical SQL query: <tt>SELECT FOO FROM MYTABLE</tt>
 * The identifier <tt>FOO</tt> is folded to lower case, so it actually
 * means <tt>foo</tt>. If you really want to access the case-sensitive
 * field name <tt>FOO</tt>, use this function like
 * <tt>PG::Connection.quote_ident('FOO')</tt>, which will return <tt>"FOO"</tt>
 * (with double-quotes). PostgreSQL will see the double-quotes, and
 * it will not fold to lower case.
 * 
 * Similarly, this function also protects against special characters,
 * and other things that might allow SQL injection if the identifier
 * comes from an untrusted source.
 */
static VALUE
pgconn_s_quote_ident(VALUE self, VALUE in_str)
{
	VALUE ret;
	char *str = StringValuePtr(in_str);
	/* result size at most NAMEDATALEN*2 plus surrounding
	 * double-quotes. */
	char buffer[NAMEDATALEN*2+2];
	unsigned int i=0,j=0;

	UNUSED( self );

	if(strlen(str) >= NAMEDATALEN) {
		rb_raise(rb_eArgError, 
			"Input string is longer than NAMEDATALEN-1 (%d)",
			NAMEDATALEN-1);
	}
	buffer[j++] = '"';
	for(i = 0; i < strlen(str) && str[i]; i++) {
		if(str[i] == '"') 
			buffer[j++] = '"';
		buffer[j++] = str[i];
	}
	buffer[j++] = '"';
	ret = rb_str_new(buffer,j);
	OBJ_INFECT(ret, in_str);
	return ret;
}


#ifndef _WIN32

/*
 * call-seq:
 *    conn.block( [ timeout ] ) -> Boolean
 *
 * Blocks until the server is no longer busy, or until the 
 * optional _timeout_ is reached, whichever comes first.
 * _timeout_ is measured in seconds and can be fractional.
 * 
 * Returns +false+ if _timeout_ is reached, +true+ otherwise.
 * 
 * If +true+ is returned, +conn.is_busy+ will return +false+
 * and +conn.get_result+ will not block.
 */
static VALUE
pgconn_block( int argc, VALUE *argv, VALUE self ) {
	PGconn *conn = pg_get_pgconn( self );
	int sd = PQsocket( conn );
	int ret;

	/* If WIN32 and Ruby 1.9 do not use rb_thread_select() which sometimes hangs 
	 * and does not wait (nor sleep) any time even if timeout is given.
	 * Instead use the Winsock events and rb_w32_wait_events(). */

	struct timeval timeout;
	struct timeval *ptimeout = NULL;
	fd_set sd_rset;
	VALUE timeout_in;
	double timeout_sec;

	if ( rb_scan_args(argc, argv, "01", &timeout_in) == 1 ) {
		timeout_sec = NUM2DBL( timeout_in );
		timeout.tv_sec = (time_t)timeout_sec;
		timeout.tv_usec = (suseconds_t)((timeout_sec - (long)timeout_sec) * 1e6);
		ptimeout = &timeout;
	}

	/* Check for connection errors (PQisBusy is true on connection errors) */
	if ( PQconsumeInput(conn) == 0 )
		rb_raise( rb_ePGerror, "%s", PQerrorMessage(conn) );

	while ( PQisBusy(conn) ) {
		FD_ZERO( &sd_rset );
		FD_SET( sd, &sd_rset );

		if ( (ret = rb_thread_select( sd+1, &sd_rset, NULL, NULL, ptimeout )) < 0 )
			rb_sys_fail( "rb_thread_select()" ); /* Raises */

		/* Return false if there was a timeout argument and the select() timed out */
		if ( ret == 0 && argc )
			return Qfalse;

		/* Check for connection errors (PQisBusy is true on connection errors) */
		if ( PQconsumeInput(conn) == 0 )
			rb_raise( rb_ePGerror, "%s", PQerrorMessage(conn) );
	}

	return Qtrue;
}


#else /* _WIN32 */

/*
 * Win32 PG::Connection#block -- on Windows, use platform-specific strategies to wait for the socket 
 * instead of rb_thread_select().
 */

/* Win32 + Ruby 1.9+ */
#ifdef HAVE_RUBY_VM_H

int rb_w32_wait_events( HANDLE *events, int num, DWORD timeout );

/* If WIN32 and Ruby 1.9 do not use rb_thread_select() which sometimes hangs 
 * and does not wait (nor sleep) any time even if timeout is given.
 * Instead use the Winsock events and rb_w32_wait_events(). */

static VALUE
pgconn_block( int argc, VALUE *argv, VALUE self ) {
	PGconn *conn = pg_get_pgconn( self );
	int sd = PQsocket( conn );
	int ret;

	DWORD timeout_milisec = INFINITY;
	DWORD wait_ret;
	WSAEVENT hEvent;
	VALUE timeout_in;
	double timeout_sec;

	hEvent = WSACreateEvent();

	if ( rb_scan_args(argc, argv, "01", &timeout_in) == 1 ) {
		timeout_sec = NUM2DBL( timeout_in );
		timeout_milisec = (DWORD)( (timeout_sec - (DWORD)timeout_sec) * 1e3 );
	}

	/* Check for connection errors (PQisBusy is true on connection errors) */
	if( PQconsumeInput(conn) == 0 ) {
		WSACloseEvent( hEvent );
		rb_raise( rb_ePGerror, PQerrorMessage(conn) );
	}

	while ( PQisBusy(conn) ) {
		if ( WSAEventSelect(sd, hEvent, FD_READ|FD_CLOSE) == SOCKET_ERROR ) {
			WSACloseEvent( hEvent );
			rb_raise( rb_ePGerror, "WSAEventSelect socket error: %d", WSAGetLastError() );
		}

		wait_ret = rb_w32_wait_events( &hEvent, 1, 100 );

		if ( wait_ret == WAIT_TIMEOUT ) {
			ret = 0;
		} else if ( wait_ret == WAIT_OBJECT_0 ) {
			ret = 1;
		} else if ( wait_ret == WAIT_FAILED ) {
			WSACloseEvent( hEvent );
			rb_raise( rb_ePGerror, "Wait on socket error (WaitForMultipleObjects): %d", GetLastError() );
		} else {
			WSACloseEvent( hEvent );
			rb_raise( rb_ePGerror, "Wait on socket abandoned (WaitForMultipleObjects)" );
		}

		/* Return false if there was a timeout argument and the select() timed out */
		if ( ret == 0 && argc ) {
			WSACloseEvent( hEvent );
			return Qfalse;
		}

		/* Check for connection errors (PQisBusy is true on connection errors) */
		if ( PQconsumeInput(conn) == 0 ) {
			WSACloseEvent( hEvent );
			rb_raise( rb_ePGerror, PQerrorMessage(conn) );
		}
	}

	WSACloseEvent( hEvent );

	return Qtrue;
}

#else /* Win32 + Ruby < 1.9 */

static VALUE
pgconn_block( int argc, VALUE *argv, VALUE self ) {
	PGconn *conn = pg_get_pgconn( self );
	int sd = PQsocket( conn );
	int ret;

	struct timeval timeout;
	struct timeval *ptimeout = NULL;
	fd_set sd_rset;
	fd_set crt_sd_rset;
	VALUE timeout_in;
	double timeout_sec;

	/* Always set a timeout, as rb_thread_select() sometimes
	 * doesn't return when a second ruby thread is running although data
	 * could be read. So we use timeout-based polling instead.
	 */
	timeout.tv_sec = 0;
	 timeout.tv_usec = 10000; /* 10ms */
	ptimeout = &timeout;

	if ( rb_scan_args(argc, argv, "01", &timeout_in) == 1 ) {
		timeout_sec = NUM2DBL( timeout_in );
		timeout.tv_sec = (time_t)timeout_sec;
		timeout.tv_usec = (suseconds_t)((timeout_sec - (long)timeout_sec) * 1e6);
		ptimeout = &timeout;
	}

	/* Check for connection errors (PQisBusy is true on connection errors) */
	if( PQconsumeInput(conn) == 0 )
		rb_raise( rb_ePGerror, PQerrorMessage(conn) );

	while ( PQisBusy(conn) ) {
		FD_ZERO( &sd_rset );
		FD_SET( sd, &sd_rset );

		create_crt_fd( &sd_rset, &crt_sd_rset );
		ret = rb_thread_select( sd+1, &sd_rset, NULL, NULL, ptimeout );
		cleanup_crt_fd( &sd_rset, &crt_sd_rset );

		/* Return false if there was a timeout argument and the select() timed out */
		if ( ret == 0 && argc )
			return Qfalse;

		/* Check for connection errors (PQisBusy is true on connection errors) */
		if ( PQconsumeInput(conn) == 0 )
			rb_raise( rb_ePGerror, PQerrorMessage(conn) );
	}

	return Qtrue;
}

#endif /* Ruby 1.9 */
#endif /* Win32 */


/*
 * call-seq:
 *    conn.get_last_result( ) -> PGresult
 *
 * This function retrieves all available results
 * on the current connection (from previously issued
 * asynchronous commands like +send_query()+) and
 * returns the last non-NULL result, or +nil+ if no
 * results are available.
 *
 * This function is similar to #get_result
 * except that it is designed to get one and only
 * one result.
 */
static VALUE
pgconn_get_last_result(VALUE self)
{
	PGconn *conn = pg_get_pgconn(self);
	VALUE rb_pgresult = Qnil;
	PGresult *cur, *prev;


	cur = prev = NULL;
	while ((cur = PQgetResult(conn)) != NULL) {
		int status;

		if (prev) PQclear(prev);
		prev = cur;

		status = PQresultStatus(cur);
		if (status == PGRES_COPY_OUT || status == PGRES_COPY_IN)
			break;
	}

	if (prev) {
		rb_pgresult = pg_new_result(prev, conn);
		pg_check_result(self, rb_pgresult);
	}

	return rb_pgresult;
}


/*
 * call-seq:
 *    conn.async_exec(sql [, params, result_format ] ) -> PGresult
 *    conn.async_exec(sql [, params, result_format ] ) {|pg_result| block }
 *
 * This function has the same behavior as #exec,
 * except that it's implemented using asynchronous command 
 * processing and ruby's +rb_thread_select+ in order to 
 * allow other threads to process while waiting for the
 * server to complete the request.
 */
static VALUE
pgconn_async_exec(int argc, VALUE *argv, VALUE self)
{
	VALUE rb_pgresult = Qnil;

	/* remove any remaining results from the queue */
	pgconn_block( 0, NULL, self ); /* wait for input (without blocking) before reading the last result */
	pgconn_get_last_result( self );

	pgconn_send_query( argc, argv, self );
	pgconn_block( 0, NULL, self );
	rb_pgresult = pgconn_get_last_result( self );

	if ( rb_block_given_p() ) {
		return rb_ensure( rb_yield, rb_pgresult, pg_result_clear, rb_pgresult );
	}
	return rb_pgresult;
}


/**************************************************************************
 * LARGE OBJECT SUPPORT
 **************************************************************************/

/*
 * call-seq:
 *    conn.lo_creat( [mode] ) -> Fixnum
 *
 * Creates a large object with mode _mode_. Returns a large object Oid.
 * On failure, it raises PGError exception.
 */
static VALUE
pgconn_locreat(int argc, VALUE *argv, VALUE self)
{
	Oid lo_oid;
	int mode;
	VALUE nmode;
	PGconn *conn = pg_get_pgconn(self);

	if (rb_scan_args(argc, argv, "01", &nmode) == 0)
		mode = INV_READ;
	else
		mode = NUM2INT(nmode);

	lo_oid = lo_creat(conn, mode);
	if (lo_oid == 0)
		rb_raise(rb_ePGerror, "lo_creat failed");

	return INT2FIX(lo_oid);
}

/*
 * call-seq:
 *    conn.lo_create( oid ) -> Fixnum
 *
 * Creates a large object with oid _oid_. Returns the large object Oid.
 * On failure, it raises PGError exception.
 */
static VALUE
pgconn_locreate(VALUE self, VALUE in_lo_oid)
{
	Oid ret, lo_oid;
	PGconn *conn = pg_get_pgconn(self);
	lo_oid = NUM2INT(in_lo_oid);

	ret = lo_create(conn, lo_oid);
	if (ret == InvalidOid)
		rb_raise(rb_ePGerror, "lo_create failed");

	return INT2FIX(ret);
}

/*
 * call-seq:
 *    conn.lo_import(file) -> Fixnum
 *
 * Import a file to a large object. Returns a large object Oid.
 *
 * On failure, it raises a PGError exception.
 */
static VALUE
pgconn_loimport(VALUE self, VALUE filename)
{
	Oid lo_oid;

	PGconn *conn = pg_get_pgconn(self);

	Check_Type(filename, T_STRING);

	lo_oid = lo_import(conn, StringValuePtr(filename));
	if (lo_oid == 0) {
		rb_raise(rb_ePGerror, "%s", PQerrorMessage(conn));
	}
	return INT2FIX(lo_oid);
}

/*
 * call-seq:
 *    conn.lo_export( oid, file ) -> nil
 *
 * Saves a large object of _oid_ to a _file_.
 */
static VALUE
pgconn_loexport(VALUE self, VALUE lo_oid, VALUE filename)
{
	PGconn *conn = pg_get_pgconn(self);
	int oid;
	Check_Type(filename, T_STRING);

	oid = NUM2INT(lo_oid);
	if (oid < 0) {
		rb_raise(rb_ePGerror, "invalid large object oid %d",oid);
	}

	if (lo_export(conn, oid, StringValuePtr(filename)) < 0) {
		rb_raise(rb_ePGerror, "%s", PQerrorMessage(conn));
	}
	return Qnil;
}

/*
 * call-seq:
 *    conn.lo_open( oid, [mode] ) -> Fixnum
 *
 * Open a large object of _oid_. Returns a large object descriptor 
 * instance on success. The _mode_ argument specifies the mode for
 * the opened large object,which is either +INV_READ+, or +INV_WRITE+.
 *
 * If _mode_ is omitted, the default is +INV_READ+.
 */
static VALUE
pgconn_loopen(int argc, VALUE *argv, VALUE self)
{
	Oid lo_oid;
	int fd, mode;
	VALUE nmode, selfid;
	PGconn *conn = pg_get_pgconn(self);

	rb_scan_args(argc, argv, "11", &selfid, &nmode);
	lo_oid = NUM2INT(selfid);
	if(NIL_P(nmode))
		mode = INV_READ;
	else
		mode = NUM2INT(nmode);

	if((fd = lo_open(conn, lo_oid, mode)) < 0) {
		rb_raise(rb_ePGerror, "can't open large object: %s", PQerrorMessage(conn));
	}
	return INT2FIX(fd);
}

/*
 * call-seq:
 *    conn.lo_write( lo_desc, buffer ) -> Fixnum
 *
 * Writes the string _buffer_ to the large object _lo_desc_.
 * Returns the number of bytes written.
 */
static VALUE
pgconn_lowrite(VALUE self, VALUE in_lo_desc, VALUE buffer)
{
	int n;
	PGconn *conn = pg_get_pgconn(self);
	int fd = NUM2INT(in_lo_desc);

	Check_Type(buffer, T_STRING);

	if( RSTRING_LEN(buffer) < 0) {
		rb_raise(rb_ePGerror, "write buffer zero string");
	}
	if((n = lo_write(conn, fd, StringValuePtr(buffer), 
				RSTRING_LEN(buffer))) < 0) {
		rb_raise(rb_ePGerror, "lo_write failed: %s", PQerrorMessage(conn));
	}

	return INT2FIX(n);
}

/*
 * call-seq:
 *    conn.lo_read( lo_desc, len ) -> String
 *
 * Attempts to read _len_ bytes from large object _lo_desc_,
 * returns resulting data.
 */
static VALUE
pgconn_loread(VALUE self, VALUE in_lo_desc, VALUE in_len)
{
	int ret;
  PGconn *conn = pg_get_pgconn(self);
	int len = NUM2INT(in_len);
	int lo_desc = NUM2INT(in_lo_desc);
	VALUE str;
	char *buffer;

  buffer = ALLOC_N(char, len);
	if(buffer == NULL)
		rb_raise(rb_eNoMemError, "ALLOC failed!");

	if (len < 0){
		rb_raise(rb_ePGerror,"nagative length %d given", len);
	}

	if((ret = lo_read(conn, lo_desc, buffer, len)) < 0)
		rb_raise(rb_ePGerror, "lo_read failed");

	if(ret == 0) {
		xfree(buffer);
		return Qnil;
	}

	str = rb_tainted_str_new(buffer, ret);
	xfree(buffer);

	return str;
}


/*
 * call-seq:
 *    conn.lo_lseek( lo_desc, offset, whence ) -> Fixnum
 *
 * Move the large object pointer _lo_desc_ to offset _offset_.
 * Valid values for _whence_ are +SEEK_SET+, +SEEK_CUR+, and +SEEK_END+.
 * (Or 0, 1, or 2.)
 */
static VALUE
pgconn_lolseek(VALUE self, VALUE in_lo_desc, VALUE offset, VALUE whence)
{
	PGconn *conn = pg_get_pgconn(self);
	int lo_desc = NUM2INT(in_lo_desc);
	int ret;

	if((ret = lo_lseek(conn, lo_desc, NUM2INT(offset), NUM2INT(whence))) < 0) {
		rb_raise(rb_ePGerror, "lo_lseek failed");
	}

	return INT2FIX(ret);
}

/*
 * call-seq:
 *    conn.lo_tell( lo_desc ) -> Fixnum
 *
 * Returns the current position of the large object _lo_desc_.
 */
static VALUE
pgconn_lotell(VALUE self, VALUE in_lo_desc)
{
	int position;
	PGconn *conn = pg_get_pgconn(self);
	int lo_desc = NUM2INT(in_lo_desc);

	if((position = lo_tell(conn, lo_desc)) < 0)
		rb_raise(rb_ePGerror,"lo_tell failed");

	return INT2FIX(position);
}

/*
 * call-seq:
 *    conn.lo_truncate( lo_desc, len ) -> nil
 *
 * Truncates the large object _lo_desc_ to size _len_.
 */
static VALUE
pgconn_lotruncate(VALUE self, VALUE in_lo_desc, VALUE in_len)
{
	PGconn *conn = pg_get_pgconn(self);
	int lo_desc = NUM2INT(in_lo_desc);
	size_t len = NUM2INT(in_len);

	if(lo_truncate(conn,lo_desc,len) < 0)
		rb_raise(rb_ePGerror,"lo_truncate failed");

	return Qnil;
}

/*
 * call-seq:
 *    conn.lo_close( lo_desc ) -> nil
 *
 * Closes the postgres large object of _lo_desc_.
 */
static VALUE
pgconn_loclose(VALUE self, VALUE in_lo_desc)
{
	PGconn *conn = pg_get_pgconn(self);
	int lo_desc = NUM2INT(in_lo_desc);

	if(lo_close(conn,lo_desc) < 0)
		rb_raise(rb_ePGerror,"lo_close failed");

	return Qnil;
}

/*
 * call-seq:
 *    conn.lo_unlink( oid ) -> nil
 *
 * Unlinks (deletes) the postgres large object of _oid_.
 */
static VALUE
pgconn_lounlink(VALUE self, VALUE in_oid)
{
	PGconn *conn = pg_get_pgconn(self);
	int oid = NUM2INT(in_oid);

	if (oid < 0)
		rb_raise(rb_ePGerror, "invalid oid %d",oid);

	if(lo_unlink(conn,oid) < 0)
		rb_raise(rb_ePGerror,"lo_unlink failed");

	return Qnil;
}


#ifdef M17N_SUPPORTED

/*
 * call-seq:
 *   conn.internal_encoding -> Encoding
 *
 * defined in Ruby 1.9 or later.
 *
 * Returns:
 * * an Encoding - client_encoding of the connection as a Ruby Encoding object.
 * * nil - the client_encoding is 'SQL_ASCII'
 */
static VALUE
pgconn_internal_encoding(VALUE self)
{
	PGconn *conn = pg_get_pgconn( self );
	rb_encoding *enc = pg_conn_enc_get( conn );

	if ( enc ) {
		return rb_enc_from_encoding( enc );
	} else {
		return Qnil;
	}
}

static VALUE pgconn_external_encoding(VALUE self);

/*
 * call-seq:
 *   conn.internal_encoding = value
 *
 * A wrapper of #set_client_encoding.
 * defined in Ruby 1.9 or later.
 *
 * +value+ can be one of:
 * * an Encoding
 * * a String - a name of Encoding
 * * +nil+ - sets the client_encoding to SQL_ASCII.
 */
static VALUE
pgconn_internal_encoding_set(VALUE self, VALUE enc)
{
	if (NIL_P(enc)) {
		pgconn_set_client_encoding( self, rb_usascii_str_new_cstr("SQL_ASCII") );
		return enc;
	}
	else if ( TYPE(enc) == T_STRING && strcasecmp("JOHAB", RSTRING_PTR(enc)) == 0 ) {
		pgconn_set_client_encoding(self, rb_usascii_str_new_cstr("JOHAB"));
		return enc;
	}
	else {
		rb_encoding *rbenc = rb_to_encoding( enc );
		const char *name = pg_get_rb_encoding_as_pg_encoding( rbenc );

		if ( PQsetClientEncoding(pg_get_pgconn( self ), name) == -1 ) {
			VALUE server_encoding = pgconn_external_encoding( self );
			rb_raise( rb_eEncCompatError, "incompatible character encodings: %s and %s",
					  rb_enc_name(rb_to_encoding(server_encoding)), name );
		}
		return enc;
	}

	rb_raise( rb_ePGerror, "unknown encoding: %s", RSTRING_PTR(rb_inspect(enc)) );

	return Qnil;
}



/*
 * call-seq:
 *   conn.external_encoding() -> Encoding
 *
 * defined in Ruby 1.9 or later.
 * - Returns the server_encoding of the connected database as a Ruby Encoding object.
 * - Maps 'SQL_ASCII' to ASCII-8BIT.
 */
static VALUE
pgconn_external_encoding(VALUE self)
{
	PGconn *conn = pg_get_pgconn( self );
	VALUE encoding = rb_iv_get( self, "@external_encoding" );
	rb_encoding *enc = NULL;
	const char *pg_encname = NULL;

	/* Use cached value if found */
	if ( RTEST(encoding) ) return encoding;

	pg_encname = PQparameterStatus( conn, "server_encoding" );
	enc = pg_get_pg_encname_as_rb_encoding( pg_encname );
	encoding = rb_enc_from_encoding( enc );

	rb_iv_set( self, "@external_encoding", encoding );

	return encoding;
}

#endif /* M17N_SUPPORTED */



void
init_pg_connection()
{
	rb_cPGconn = rb_define_class_under( rb_mPG, "Connection", rb_cObject );
	rb_include_module(rb_cPGconn, rb_mPGconstants);
	
	/******     PG::Connection CLASS METHODS     ******/
	rb_define_alloc_func( rb_cPGconn, pgconn_s_allocate );

	SINGLETON_ALIAS(rb_cPGconn, "connect", "new");
	SINGLETON_ALIAS(rb_cPGconn, "open", "new");
	SINGLETON_ALIAS(rb_cPGconn, "setdb", "new");
	SINGLETON_ALIAS(rb_cPGconn, "setdblogin", "new");
	rb_define_singleton_method(rb_cPGconn, "escape_string", pgconn_s_escape, 1);
	SINGLETON_ALIAS(rb_cPGconn, "escape", "escape_string");
	rb_define_singleton_method(rb_cPGconn, "escape_bytea", pgconn_s_escape_bytea, 1);
	rb_define_singleton_method(rb_cPGconn, "unescape_bytea", pgconn_s_unescape_bytea, 1);
	rb_define_singleton_method(rb_cPGconn, "isthreadsafe", pgconn_s_isthreadsafe, 0);
	rb_define_singleton_method(rb_cPGconn, "encrypt_password", pgconn_s_encrypt_password, 2);
	rb_define_singleton_method(rb_cPGconn, "quote_ident", pgconn_s_quote_ident, 1);
	rb_define_singleton_method(rb_cPGconn, "connect_start", pgconn_s_connect_start, -1);
	rb_define_singleton_method(rb_cPGconn, "conndefaults", pgconn_s_conndefaults, 0);

	/******     PG::Connection INSTANCE METHODS: Connection Control     ******/
	rb_define_method(rb_cPGconn, "initialize", pgconn_init, -1);
	rb_define_method(rb_cPGconn, "connect_poll", pgconn_connect_poll, 0);
	rb_define_method(rb_cPGconn, "finish", pgconn_finish, 0);
	rb_define_method(rb_cPGconn, "finished?", pgconn_finished_p, 0);
	rb_define_method(rb_cPGconn, "reset", pgconn_reset, 0);
	rb_define_method(rb_cPGconn, "reset_start", pgconn_reset_start, 0);
	rb_define_method(rb_cPGconn, "reset_poll", pgconn_reset_poll, 0);
	rb_define_method(rb_cPGconn, "conndefaults", pgconn_s_conndefaults, 0);
	rb_define_alias(rb_cPGconn, "close", "finish");

	/******     PG::Connection INSTANCE METHODS: Connection Status     ******/
	rb_define_method(rb_cPGconn, "db", pgconn_db, 0);
	rb_define_method(rb_cPGconn, "user", pgconn_user, 0);
	rb_define_method(rb_cPGconn, "pass", pgconn_pass, 0);
	rb_define_method(rb_cPGconn, "host", pgconn_host, 0);
	rb_define_method(rb_cPGconn, "port", pgconn_port, 0);
	rb_define_method(rb_cPGconn, "tty", pgconn_tty, 0);
	rb_define_method(rb_cPGconn, "options", pgconn_options, 0);
	rb_define_method(rb_cPGconn, "status", pgconn_status, 0);
	rb_define_method(rb_cPGconn, "transaction_status", pgconn_transaction_status, 0);
	rb_define_method(rb_cPGconn, "parameter_status", pgconn_parameter_status, 1);
	rb_define_method(rb_cPGconn, "protocol_version", pgconn_protocol_version, 0);
	rb_define_method(rb_cPGconn, "server_version", pgconn_server_version, 0);
	rb_define_method(rb_cPGconn, "error_message", pgconn_error_message, 0);
	rb_define_method(rb_cPGconn, "socket", pgconn_socket, 0);
	rb_define_method(rb_cPGconn, "backend_pid", pgconn_backend_pid, 0);
	rb_define_method(rb_cPGconn, "connection_needs_password", pgconn_connection_needs_password, 0);
	rb_define_method(rb_cPGconn, "connection_used_password", pgconn_connection_used_password, 0);
	/* rb_define_method(rb_cPGconn, "getssl", pgconn_getssl, 0); */

	/******     PG::Connection INSTANCE METHODS: Command Execution     ******/
	rb_define_method(rb_cPGconn, "exec", pgconn_exec, -1);
	rb_define_alias(rb_cPGconn, "query", "exec");
	rb_define_method(rb_cPGconn, "prepare", pgconn_prepare, -1);
	rb_define_method(rb_cPGconn, "exec_prepared", pgconn_exec_prepared, -1);
	rb_define_method(rb_cPGconn, "describe_prepared", pgconn_describe_prepared, 1);
	rb_define_method(rb_cPGconn, "describe_portal", pgconn_describe_portal, 1);
	rb_define_method(rb_cPGconn, "make_empty_pgresult", pgconn_make_empty_pgresult, 1);
	rb_define_method(rb_cPGconn, "escape_string", pgconn_s_escape, 1);
	rb_define_alias(rb_cPGconn, "escape", "escape_string");
	rb_define_method(rb_cPGconn, "escape_bytea", pgconn_s_escape_bytea, 1);
	rb_define_method(rb_cPGconn, "unescape_bytea", pgconn_s_unescape_bytea, 1);

	/******     PG::Connection INSTANCE METHODS: Asynchronous Command Processing     ******/
	rb_define_method(rb_cPGconn, "send_query", pgconn_send_query, -1);
	rb_define_method(rb_cPGconn, "send_prepare", pgconn_send_prepare, -1);
	rb_define_method(rb_cPGconn, "send_query_prepared", pgconn_send_query_prepared, -1);
	rb_define_method(rb_cPGconn, "send_describe_prepared", pgconn_send_describe_prepared, 1);
	rb_define_method(rb_cPGconn, "send_describe_portal", pgconn_send_describe_portal, 1);
	rb_define_method(rb_cPGconn, "get_result", pgconn_get_result, 0);
	rb_define_method(rb_cPGconn, "consume_input", pgconn_consume_input, 0);
	rb_define_method(rb_cPGconn, "is_busy", pgconn_is_busy, 0);
	rb_define_method(rb_cPGconn, "setnonblocking", pgconn_setnonblocking, 1);
	rb_define_method(rb_cPGconn, "isnonblocking", pgconn_isnonblocking, 0);
	rb_define_alias(rb_cPGconn, "nonblocking?", "isnonblocking");
	rb_define_method(rb_cPGconn, "flush", pgconn_flush, 0);

	/******     PG::Connection INSTANCE METHODS: Cancelling Queries in Progress     ******/
	rb_define_method(rb_cPGconn, "cancel", pgconn_cancel, 0);

	/******     PG::Connection INSTANCE METHODS: NOTIFY     ******/
	rb_define_method(rb_cPGconn, "notifies", pgconn_notifies, 0);

	/******     PG::Connection INSTANCE METHODS: COPY     ******/
	rb_define_method(rb_cPGconn, "put_copy_data", pgconn_put_copy_data, 1);
	rb_define_method(rb_cPGconn, "put_copy_end", pgconn_put_copy_end, -1);
	rb_define_method(rb_cPGconn, "get_copy_data", pgconn_get_copy_data, -1);

	/******     PG::Connection INSTANCE METHODS: Control Functions     ******/
	rb_define_method(rb_cPGconn, "set_error_verbosity", pgconn_set_error_verbosity, 1);
	rb_define_method(rb_cPGconn, "trace", pgconn_trace, 1);
	rb_define_method(rb_cPGconn, "untrace", pgconn_untrace, 0);

	/******     PG::Connection INSTANCE METHODS: Notice Processing     ******/
	rb_define_method(rb_cPGconn, "set_notice_receiver", pgconn_set_notice_receiver, 0);
	rb_define_method(rb_cPGconn, "set_notice_processor", pgconn_set_notice_processor, 0);

	/******     PG::Connection INSTANCE METHODS: Other    ******/
	rb_define_method(rb_cPGconn, "get_client_encoding", pgconn_get_client_encoding, 0);
	rb_define_method(rb_cPGconn, "set_client_encoding", pgconn_set_client_encoding, 1);
	rb_define_alias(rb_cPGconn, "client_encoding=", "set_client_encoding");
	rb_define_method(rb_cPGconn, "transaction", pgconn_transaction, 0);
	rb_define_method(rb_cPGconn, "block", pgconn_block, -1);
	rb_define_method(rb_cPGconn, "wait_for_notify", pgconn_wait_for_notify, -1);
	rb_define_alias(rb_cPGconn, "notifies_wait", "wait_for_notify");
	rb_define_method(rb_cPGconn, "quote_ident", pgconn_s_quote_ident, 1);
	rb_define_method(rb_cPGconn, "async_exec", pgconn_async_exec, -1);
	rb_define_alias(rb_cPGconn, "async_query", "async_exec");
	rb_define_method(rb_cPGconn, "get_last_result", pgconn_get_last_result, 0);

	/******     PG::Connection INSTANCE METHODS: Large Object Support     ******/
	rb_define_method(rb_cPGconn, "lo_creat", pgconn_locreat, -1);
	rb_define_alias(rb_cPGconn, "locreat", "lo_creat");
	rb_define_method(rb_cPGconn, "lo_create", pgconn_locreate, 1);
	rb_define_alias(rb_cPGconn, "locreate", "lo_create");
	rb_define_method(rb_cPGconn, "lo_import", pgconn_loimport, 1);
	rb_define_alias(rb_cPGconn, "loimport", "lo_import");
	rb_define_method(rb_cPGconn, "lo_export", pgconn_loexport, 2);
	rb_define_alias(rb_cPGconn, "loexport", "lo_export");
	rb_define_method(rb_cPGconn, "lo_open", pgconn_loopen, -1);
	rb_define_alias(rb_cPGconn, "loopen", "lo_open");
	rb_define_method(rb_cPGconn, "lo_write",pgconn_lowrite, 2);
	rb_define_alias(rb_cPGconn, "lowrite", "lo_write");
	rb_define_method(rb_cPGconn, "lo_read",pgconn_loread, 2);
	rb_define_alias(rb_cPGconn, "loread", "lo_read");
	rb_define_method(rb_cPGconn, "lo_lseek",pgconn_lolseek, 3);
	rb_define_alias(rb_cPGconn, "lolseek", "lo_lseek");
	rb_define_alias(rb_cPGconn, "lo_seek", "lo_lseek");
	rb_define_alias(rb_cPGconn, "loseek", "lo_lseek");
	rb_define_method(rb_cPGconn, "lo_tell",pgconn_lotell, 1);
	rb_define_alias(rb_cPGconn, "lotell", "lo_tell");
	rb_define_method(rb_cPGconn, "lo_truncate", pgconn_lotruncate, 2);
	rb_define_alias(rb_cPGconn, "lotruncate", "lo_truncate");
	rb_define_method(rb_cPGconn, "lo_close",pgconn_loclose, 1);
	rb_define_alias(rb_cPGconn, "loclose", "lo_close");
	rb_define_method(rb_cPGconn, "lo_unlink", pgconn_lounlink, 1);
	rb_define_alias(rb_cPGconn, "lounlink", "lo_unlink");

#ifdef M17N_SUPPORTED
	rb_define_method(rb_cPGconn, "internal_encoding", pgconn_internal_encoding, 0);
	rb_define_method(rb_cPGconn, "internal_encoding=", pgconn_internal_encoding_set, 1);
	rb_define_method(rb_cPGconn, "external_encoding", pgconn_external_encoding, 0);
#endif /* M17N_SUPPORTED */

}


