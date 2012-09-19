/*
 * pg_result.c - PG::Result class extension
 * $Id: pg_result.c,v 1cdad2ce8993 2012/01/25 01:21:30 ged $
 *
 */

#include "pg.h"


VALUE rb_cPGresult;

static void pgresult_gc_free( PGresult * );
static PGresult* pgresult_get( VALUE );


/*
 * Global functions
 */

/*
 * Result constructor
 */
VALUE
pg_new_result(PGresult *result, PGconn *conn)
{
	VALUE val = Data_Wrap_Struct(rb_cPGresult, NULL, pgresult_gc_free, result);
#ifdef M17N_SUPPORTED
	rb_encoding *enc = pg_conn_enc_get( conn );
	ENCODING_SET( val, rb_enc_to_index(enc) );
#endif

	return val;
}

/*
 * Raises appropriate exception if PGresult is
 * in a bad state.
 */
void
pg_check_result(VALUE rb_pgconn, VALUE rb_pgresult)
{
	VALUE error, exception;
	PGconn *conn = pg_get_pgconn(rb_pgconn);
	PGresult *result;
#ifdef M17N_SUPPORTED
	rb_encoding *enc = pg_conn_enc_get( conn );
#endif

	Data_Get_Struct(rb_pgresult, PGresult, result);

	if(result == NULL)
	{
		error = rb_str_new2( PQerrorMessage(conn) );
	}
	else
	{
		switch (PQresultStatus(result))
		{
		case PGRES_TUPLES_OK:
		case PGRES_COPY_OUT:
		case PGRES_COPY_IN:
		case PGRES_EMPTY_QUERY:
		case PGRES_COMMAND_OK:
			return;
		case PGRES_BAD_RESPONSE:
		case PGRES_FATAL_ERROR:
		case PGRES_NONFATAL_ERROR:
			error = rb_str_new2( PQresultErrorMessage(result) );
			break;
		default:
			error = rb_str_new2( "internal error : unknown result status." );
		}
	}

#ifdef M17N_SUPPORTED
	rb_enc_set_index( error, rb_enc_to_index(enc) );
#endif
	exception = rb_exc_new3( rb_ePGerror, error );
	rb_iv_set( exception, "@connection", rb_pgconn );
	rb_iv_set( exception, "@result", rb_pgresult );
	rb_exc_raise( exception );

	return;
}


/*
 * :TODO: This shouldn't be a global function, but it needs to be as long as pg_new_result
 * doesn't handle blocks, check results, etc. Once connection and result are disentangled
 * a bit more, I can make this a static pgresult_clear() again.
 */

/*
 * call-seq:
 *    res.clear() -> nil
 *
 * Clears the PGresult object as the result of the query.
 */
VALUE
pg_result_clear(VALUE self)
{
	PQclear(pgresult_get(self));
	DATA_PTR(self) = NULL;
	return Qnil;
}



/*
 * DATA pointer functions
 */

/*
 * GC Free function
 */
static void
pgresult_gc_free( PGresult *result )
{
	if(result != NULL)
		PQclear(result);
}

/*
 * Fetch the data pointer for the result object
 */
static PGresult*
pgresult_get(VALUE self)
{
	PGresult *result;
	Data_Get_Struct(self, PGresult, result);
	if (result == NULL) rb_raise(rb_ePGerror, "result has been cleared");
	return result;
}


/********************************************************************
 * 
 * Document-class: PGresult
 *
 * The class to represent the query result tuples (rows). 
 * An instance of this class is created as the result of every query.
 * You may need to invoke the #clear method of the instance when finished with
 * the result for better memory performance.
 *
 * Example:
 *    require 'pg'
 *    conn = PGconn.open(:dbname => 'test')
 *    res  = conn.exec('SELECT 1 AS a, 2 AS b, NULL AS c')
 *    res.getvalue(0,0) # '1'
 *    res[0]['b']       # '2'
 *    res[0]['c']       # nil
 *  
 */

/**************************************************************************
 * PGresult INSTANCE METHODS
 **************************************************************************/

/*
 * call-seq:
 *    res.result_status() -> Fixnum
 *
 * Returns the status of the query. The status value is one of:
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
pgresult_result_status(VALUE self)
{
	return INT2FIX(PQresultStatus(pgresult_get(self)));
}

/*
 * call-seq:
 *    res.res_status( status ) -> String
 *
 * Returns the string representation of status +status+.
 *
*/
static VALUE
pgresult_res_status(VALUE self, VALUE status)
{
	VALUE ret = rb_tainted_str_new2(PQresStatus(NUM2INT(status)));
	ASSOCIATE_INDEX(ret, self);
	return ret;
}

/*
 * call-seq:
 *    res.error_message() -> String
 *
 * Returns the error message of the command as a string. 
 */
static VALUE
pgresult_error_message(VALUE self)
{
	VALUE ret = rb_tainted_str_new2(PQresultErrorMessage(pgresult_get(self)));
	ASSOCIATE_INDEX(ret, self);
	return ret;
}

/*
 * call-seq:
 *    res.error_field(fieldcode) -> String
 *
 * Returns the individual field of an error.
 *
 * +fieldcode+ is one of:
 * * +PG_DIAG_SEVERITY+
 * * +PG_DIAG_SQLSTATE+
 * * +PG_DIAG_MESSAGE_PRIMARY+
 * * +PG_DIAG_MESSAGE_DETAIL+
 * * +PG_DIAG_MESSAGE_HINT+
 * * +PG_DIAG_STATEMENT_POSITION+
 * * +PG_DIAG_INTERNAL_POSITION+
 * * +PG_DIAG_INTERNAL_QUERY+
 * * +PG_DIAG_CONTEXT+
 * * +PG_DIAG_SOURCE_FILE+
 * * +PG_DIAG_SOURCE_LINE+
 * * +PG_DIAG_SOURCE_FUNCTION+
 *
 * An example:
 * 
 *   begin
 *       conn.exec( "SELECT * FROM nonexistant_table" )
 *   rescue PGError => err
 *       p [
 *           result.error_field( PGresult::PG_DIAG_SEVERITY ),
 *           result.error_field( PGresult::PG_DIAG_SQLSTATE ),
 *           result.error_field( PGresult::PG_DIAG_MESSAGE_PRIMARY ),
 *           result.error_field( PGresult::PG_DIAG_MESSAGE_DETAIL ),
 *           result.error_field( PGresult::PG_DIAG_MESSAGE_HINT ),
 *           result.error_field( PGresult::PG_DIAG_STATEMENT_POSITION ),
 *           result.error_field( PGresult::PG_DIAG_INTERNAL_POSITION ),
 *           result.error_field( PGresult::PG_DIAG_INTERNAL_QUERY ),
 *           result.error_field( PGresult::PG_DIAG_CONTEXT ),
 *           result.error_field( PGresult::PG_DIAG_SOURCE_FILE ),
 *           result.error_field( PGresult::PG_DIAG_SOURCE_LINE ),
 *           result.error_field( PGresult::PG_DIAG_SOURCE_FUNCTION ),
 *       ]
 *   end
 * 
 * Outputs:
 * 
 *   ["ERROR", "42P01", "relation \"nonexistant_table\" does not exist", nil, nil, 
 *    "15", nil, nil, nil, "path/to/parse_relation.c", "857", "parserOpenTable"]
 */
static VALUE
pgresult_error_field(VALUE self, VALUE field)
{
	PGresult *result = pgresult_get( self );
	int fieldcode = NUM2INT( field );
	char * fieldstr = PQresultErrorField( result, fieldcode );
	VALUE ret = Qnil;

	if ( fieldstr ) {
		ret = rb_tainted_str_new2( fieldstr );
		ASSOCIATE_INDEX( ret, self );
	}

	return ret;
}

/*
 * call-seq:
 *    res.ntuples() -> Fixnum
 *
 * Returns the number of tuples in the query result.
 */
static VALUE
pgresult_ntuples(VALUE self)
{
	return INT2FIX(PQntuples(pgresult_get(self)));
}

/*
 * call-seq:
 *    res.nfields() -> Fixnum
 *
 * Returns the number of columns in the query result.
 */
static VALUE
pgresult_nfields(VALUE self)
{
	return INT2NUM(PQnfields(pgresult_get(self)));
}

/*
 * call-seq:
 *    res.fname( index ) -> String
 *
 * Returns the name of the column corresponding to _index_.
 */
static VALUE
pgresult_fname(VALUE self, VALUE index)
{
	VALUE fname;
	PGresult *result;
	int i = NUM2INT(index);

	result = pgresult_get(self);
	if (i < 0 || i >= PQnfields(result)) {
		rb_raise(rb_eArgError,"invalid field number %d", i);
	}
	fname = rb_tainted_str_new2(PQfname(result, i));
	ASSOCIATE_INDEX(fname, self);
	return fname;
}

/*
 * call-seq:
 *    res.fnumber( name ) -> Fixnum
 *
 * Returns the index of the field specified by the string _name_.
 *
 * Raises an ArgumentError if the specified _name_ isn't one of the field names;
 * raises a TypeError if _name_ is not a String.
 */
static VALUE
pgresult_fnumber(VALUE self, VALUE name)
{
	int n;

	Check_Type(name, T_STRING);

	n = PQfnumber(pgresult_get(self), StringValuePtr(name));
	if (n == -1) {
		rb_raise(rb_eArgError,"Unknown field: %s", StringValuePtr(name));
	}
	return INT2FIX(n);
}

/*
 * call-seq:
 *    res.ftable( column_number ) -> Fixnum
 *
 * Returns the Oid of the table from which the column _column_number_
 * was fetched.
 *
 * Raises ArgumentError if _column_number_ is out of range or if
 * the Oid is undefined for that column.
 */
static VALUE
pgresult_ftable(VALUE self, VALUE column_number)
{
	Oid n ;
	int col_number = NUM2INT(column_number);
	PGresult *pgresult = pgresult_get(self);

	if( col_number < 0 || col_number >= PQnfields(pgresult)) 
		rb_raise(rb_eArgError,"Invalid column index: %d", col_number);

	n = PQftable(pgresult, col_number);
	return INT2FIX(n);
}

/*
 * call-seq:
 *    res.ftablecol( column_number ) -> Fixnum
 *
 * Returns the column number (within its table) of the table from 
 * which the column _column_number_ is made up.
 *
 * Raises ArgumentError if _column_number_ is out of range or if
 * the column number from its table is undefined for that column.
 */
static VALUE
pgresult_ftablecol(VALUE self, VALUE column_number)
{
	int col_number = NUM2INT(column_number);
	PGresult *pgresult = pgresult_get(self);

	int n;

	if( col_number < 0 || col_number >= PQnfields(pgresult)) 
		rb_raise(rb_eArgError,"Invalid column index: %d", col_number);

	n = PQftablecol(pgresult, col_number);
	return INT2FIX(n);
}

/*
 * call-seq:
 *    res.fformat( column_number ) -> Fixnum
 *
 * Returns the format (0 for text, 1 for binary) of column
 * _column_number_.
 * 
 * Raises ArgumentError if _column_number_ is out of range.
 */
static VALUE
pgresult_fformat(VALUE self, VALUE column_number)
{
	PGresult *result = pgresult_get(self);
	int fnumber = NUM2INT(column_number);
	if (fnumber < 0 || fnumber >= PQnfields(result)) {
		rb_raise(rb_eArgError, "Column number is out of range: %d", 
			fnumber);
	}
	return INT2FIX(PQfformat(result, fnumber));
}

/*
 * call-seq:
 *    res.ftype( column_number )
 *
 * Returns the data type associated with _column_number_.
 *
 * The integer returned is the internal +OID+ number (in PostgreSQL)
 * of the type. To get a human-readable value for the type, use the
 * returned OID and the field's #fmod value with the format_type() SQL 
 * function:
 * 
 *   # Get the type of the second column of the result 'res'
 *   typename = conn.
 *     exec( "SELECT format_type($1,$2)", [res.ftype(1), res.fmod(1)] ).
 *     getvalue( 0, 0 )
 * 
 * Raises an ArgumentError if _column_number_ is out of range.
 */
static VALUE
pgresult_ftype(VALUE self, VALUE index)
{
	PGresult* result = pgresult_get(self);
	int i = NUM2INT(index);
	if (i < 0 || i >= PQnfields(result)) {
		rb_raise(rb_eArgError, "invalid field number %d", i);
	}
	return INT2NUM(PQftype(result, i));
}

/*
 * call-seq:
 *    res.fmod( column_number )
 *
 * Returns the type modifier associated with column _column_number_. See 
 * the #ftype method for an example of how to use this.
 * 
 * Raises an ArgumentError if _column_number_ is out of range.
 */
static VALUE
pgresult_fmod(VALUE self, VALUE column_number)
{
	PGresult *result = pgresult_get(self);
	int fnumber = NUM2INT(column_number);
	int modifier;
	if (fnumber < 0 || fnumber >= PQnfields(result)) {
		rb_raise(rb_eArgError, "Column number is out of range: %d", 
			fnumber);
	}
	modifier = PQfmod(result,fnumber);

	return INT2NUM(modifier);
}

/*
 * call-seq:
 *    res.fsize( index )
 *
 * Returns the size of the field type in bytes.  Returns <tt>-1</tt> if the field is variable sized.
 *
 *   res = conn.exec("SELECT myInt, myVarChar50 FROM foo")
 *   res.size(0) => 4
 *   res.size(1) => -1
 */
static VALUE
pgresult_fsize(VALUE self, VALUE index)
{
	PGresult *result;
	int i = NUM2INT(index);

	result = pgresult_get(self);
	if (i < 0 || i >= PQnfields(result)) {
		rb_raise(rb_eArgError,"invalid field number %d", i);
	}
	return INT2NUM(PQfsize(result, i));
}

/*
 * call-seq:
 *    res.getvalue( tup_num, field_num )
 *
 * Returns the value in tuple number _tup_num_, field _field_num_,
 * or +nil+ if the field is +NULL+.
 */
static VALUE
pgresult_getvalue(VALUE self, VALUE tup_num, VALUE field_num)
{
	VALUE ret;
	PGresult *result;
	int i = NUM2INT(tup_num);
	int j = NUM2INT(field_num);

	result = pgresult_get(self);
	if(i < 0 || i >= PQntuples(result)) {
		rb_raise(rb_eArgError,"invalid tuple number %d", i);
	}
	if(j < 0 || j >= PQnfields(result)) {
		rb_raise(rb_eArgError,"invalid field number %d", j);
	}
	if(PQgetisnull(result, i, j))
		return Qnil;
	ret = rb_tainted_str_new(PQgetvalue(result, i, j), 
				PQgetlength(result, i, j));
	ASSOCIATE_INDEX(ret, self);
	return ret;
}

/*
 * call-seq:
 *    res.getisnull(tuple_position, field_position) -> boolean
 *
 * Returns +true+ if the specified value is +nil+; +false+ otherwise.
 */
static VALUE
pgresult_getisnull(VALUE self, VALUE tup_num, VALUE field_num)
{
	PGresult *result;
	int i = NUM2INT(tup_num);
	int j = NUM2INT(field_num);

	result = pgresult_get(self);
	if (i < 0 || i >= PQntuples(result)) {
		rb_raise(rb_eArgError,"invalid tuple number %d", i);
	}
	if (j < 0 || j >= PQnfields(result)) {
		rb_raise(rb_eArgError,"invalid field number %d", j);
	}
	return PQgetisnull(result, i, j) ? Qtrue : Qfalse;
}

/*
 * call-seq:
 *    res.getlength( tup_num, field_num ) -> Fixnum
 *
 * Returns the (String) length of the field in bytes.
 *
 * Equivalent to <tt>res.value(<i>tup_num</i>,<i>field_num</i>).length</tt>.
 */
static VALUE
pgresult_getlength(VALUE self, VALUE tup_num, VALUE field_num)
{
	PGresult *result;
	int i = NUM2INT(tup_num);
	int j = NUM2INT(field_num);

	result = pgresult_get(self);
	if (i < 0 || i >= PQntuples(result)) {
		rb_raise(rb_eArgError,"invalid tuple number %d", i);
	}
	if (j < 0 || j >= PQnfields(result)) {
		rb_raise(rb_eArgError,"invalid field number %d", j);
	}
	return INT2FIX(PQgetlength(result, i, j));
}

/*
 * call-seq:
 *    res.nparams() -> Fixnum
 *
 * Returns the number of parameters of a prepared statement.
 * Only useful for the result returned by conn.describePrepared
 */
static VALUE
pgresult_nparams(VALUE self)
{
	PGresult *result;

	result = pgresult_get(self);
	return INT2FIX(PQnparams(result));
}

/*
 * call-seq:
 *    res.paramtype( param_number ) -> Oid
 *
 * Returns the Oid of the data type of parameter _param_number_.
 * Only useful for the result returned by conn.describePrepared
 */
static VALUE
pgresult_paramtype(VALUE self, VALUE param_number)
{
	PGresult *result;

	result = pgresult_get(self);
	return INT2FIX(PQparamtype(result,NUM2INT(param_number)));
}

/*
 * call-seq:
 *    res.cmd_status() -> String
 *
 * Returns the status string of the last query command.
 */
static VALUE
pgresult_cmd_status(VALUE self)
{
	VALUE ret = rb_tainted_str_new2(PQcmdStatus(pgresult_get(self)));
	ASSOCIATE_INDEX(ret, self);
	return ret;
}

/*
 * call-seq:
 *    res.cmd_tuples() -> Fixnum
 *
 * Returns the number of tuples (rows) affected by the SQL command.
 *
 * If the SQL command that generated the PGresult was not one of:
 * * +INSERT+
 * * +UPDATE+
 * * +DELETE+
 * * +MOVE+
 * * +FETCH+
 * or if no tuples were affected, <tt>0</tt> is returned.
 */
static VALUE
pgresult_cmd_tuples(VALUE self)
{
	long n;
	n = strtol(PQcmdTuples(pgresult_get(self)),NULL, 10);
	return INT2NUM(n);
}

/*
 * call-seq:
 *    res.oid_value() -> Fixnum
 *
 * Returns the +oid+ of the inserted row if applicable,
 * otherwise +nil+.
 */
static VALUE
pgresult_oid_value(VALUE self)
{
	Oid n = PQoidValue(pgresult_get(self));
	if (n == InvalidOid)
		return Qnil;
	else
		return INT2FIX(n);
}

/* Utility methods not in libpq */

/*
 * call-seq:
 *    res[ n ] -> Hash
 *
 * Returns tuple _n_ as a hash. 
 */
static VALUE
pgresult_aref(VALUE self, VALUE index)
{
	PGresult *result = pgresult_get(self);
	int tuple_num = NUM2INT(index);
	int field_num;
	VALUE fname,val;
	VALUE tuple;

	if ( tuple_num < 0 || tuple_num >= PQntuples(result) )
		rb_raise( rb_eIndexError, "Index %d is out of range", tuple_num );

	tuple = rb_hash_new();
	for ( field_num = 0; field_num < PQnfields(result); field_num++ ) {
		fname = rb_tainted_str_new2( PQfname(result,field_num) );
		ASSOCIATE_INDEX(fname, self);
		if ( PQgetisnull(result, tuple_num, field_num) ) {
			rb_hash_aset( tuple, fname, Qnil );
		}
		else {
			val = rb_tainted_str_new( PQgetvalue(result, tuple_num, field_num ),
			                          PQgetlength(result, tuple_num, field_num) );

#ifdef M17N_SUPPORTED
			/* associate client encoding for text format only */
			if ( 0 == PQfformat(result, field_num) ) {
				ASSOCIATE_INDEX( val, self );
			} else {
				rb_enc_associate( val, rb_ascii8bit_encoding() );
			}
#endif

			rb_hash_aset( tuple, fname, val );
		}
	}
	return tuple;
}


/*
 * call-seq:
 *    res.values -> Array
 *
 * Returns all tuples as an array of arrays.
 */
static VALUE
pgresult_values(VALUE self)
{
	PGresult* result = (PGresult*) pgresult_get(self);
	int row;
	int field;
	int num_rows = PQntuples(result);
	int num_fields = PQnfields(result);
	VALUE ary = rb_ary_new2(num_rows);

	for ( row = 0; row < num_rows; row++ ) {
		/* create new row */
		VALUE new_row = rb_ary_new2(num_fields);

		/* add to return array */
		rb_ary_store( ary, row, new_row );

		/* populate it */
		for ( field = 0; field < num_fields; field++ ) {
			if ( PQgetisnull(result, row, field) ) {
				rb_ary_store( new_row, field, Qnil );
			}
			else {
				VALUE val = rb_tainted_str_new( PQgetvalue(result, row, field), 
				                                PQgetlength(result, row, field) );

#ifdef M17N_SUPPORTED
				/* associate client encoding for text format only */
				if ( 0 == PQfformat(result, field) ) {
					ASSOCIATE_INDEX( val, self );
				} else {
					rb_enc_associate( val, rb_ascii8bit_encoding() );
				}
#endif

				rb_ary_store( new_row, field, val );
			}
		}
	}
	return ary;
}


/* 
 * Make a Ruby array out of the encoded values from the specified
 * column in the given result.
 */
static VALUE
make_column_result_array( VALUE self, int col )
{
	PGresult *result = pgresult_get( self );
	int row = PQntuples( result );
	VALUE ary = rb_ary_new2( row );
	VALUE val = Qnil;

	if ( col >= PQnfields(result) )
		rb_raise( rb_eIndexError, "no column %d in result", col );

	while ( row-- ) {
		val = rb_tainted_str_new( PQgetvalue(result, row, col),
		                          PQgetlength(result, row, col) );

#ifdef M17N_SUPPORTED
		/* associate client encoding for text format only */
		if ( 0 == PQfformat(result, col) ) { 
			ASSOCIATE_INDEX( val, self );
		} else {
			rb_enc_associate( val, rb_ascii8bit_encoding() );
		}
#endif

		rb_ary_store( ary, row, val );
	}

	return ary;
}


/*
 *  call-seq:
 *     res.column_values( n )   -> array
 *
 *  Returns an Array of the values from the nth column of each 
 *  tuple in the result.
 *
 */
static VALUE
pgresult_column_values(VALUE self, VALUE index)
{
	int col = NUM2INT( index );
	return make_column_result_array( self, col );
}


/*
 *  call-seq:
 *     res.field_values( field )   -> array
 *
 *  Returns an Array of the values from the given _field_ of each tuple in the result.
 *
 */
static VALUE
pgresult_field_values( VALUE self, VALUE field )
{
	PGresult *result = pgresult_get( self );
	const char *fieldname = RSTRING_PTR( field );
	int fnum = PQfnumber( result, fieldname );

	if ( fnum < 0 )
		rb_raise( rb_eIndexError, "no such field '%s' in result", fieldname );

	return make_column_result_array( self, fnum );
}


/*
 * call-seq:
 *    res.each{ |tuple| ... }
 *
 * Invokes block for each tuple in the result set.
 */
static VALUE
pgresult_each(VALUE self)
{
	PGresult *result = pgresult_get(self);
	int tuple_num;

	for(tuple_num = 0; tuple_num < PQntuples(result); tuple_num++) {
		rb_yield(pgresult_aref(self, INT2NUM(tuple_num)));
	}
	return self;
}

/*
 * call-seq:
 *    res.fields() -> Array
 *
 * Returns an array of Strings representing the names of the fields in the result.
 */
static VALUE
pgresult_fields(VALUE self)
{
	PGresult *result;
	VALUE ary;
	int n, i;

	result = pgresult_get(self);
	n = PQnfields(result);
	ary = rb_ary_new2(n);
	for (i=0;i<n;i++) {
		VALUE val = rb_tainted_str_new2(PQfname(result, i));
		ASSOCIATE_INDEX(val, self);
		rb_ary_push(ary, val);
	}
	return ary;
}


void
init_pg_result()
{
	rb_cPGresult = rb_define_class_under( rb_mPG, "Result", rb_cObject );
	rb_include_module(rb_cPGresult, rb_mEnumerable);
	rb_include_module(rb_cPGresult, rb_mPGconstants);

	/******     PG::Result INSTANCE METHODS: libpq     ******/
	rb_define_method(rb_cPGresult, "result_status", pgresult_result_status, 0);
	rb_define_method(rb_cPGresult, "res_status", pgresult_res_status, 1);
	rb_define_method(rb_cPGresult, "error_message", pgresult_error_message, 0);
	rb_define_alias( rb_cPGresult, "result_error_message", "error_message");
	rb_define_method(rb_cPGresult, "error_field", pgresult_error_field, 1);
	rb_define_alias( rb_cPGresult, "result_error_field", "error_field" );
	rb_define_method(rb_cPGresult, "clear", pg_result_clear, 0);
	rb_define_method(rb_cPGresult, "ntuples", pgresult_ntuples, 0);
	rb_define_alias(rb_cPGresult, "num_tuples", "ntuples");
	rb_define_method(rb_cPGresult, "nfields", pgresult_nfields, 0);
	rb_define_alias(rb_cPGresult, "num_fields", "nfields");
	rb_define_method(rb_cPGresult, "fname", pgresult_fname, 1);
	rb_define_method(rb_cPGresult, "fnumber", pgresult_fnumber, 1);
	rb_define_method(rb_cPGresult, "ftable", pgresult_ftable, 1);
	rb_define_method(rb_cPGresult, "ftablecol", pgresult_ftablecol, 1);
	rb_define_method(rb_cPGresult, "fformat", pgresult_fformat, 1);
	rb_define_method(rb_cPGresult, "ftype", pgresult_ftype, 1);
	rb_define_method(rb_cPGresult, "fmod", pgresult_fmod, 1);
	rb_define_method(rb_cPGresult, "fsize", pgresult_fsize, 1);
	rb_define_method(rb_cPGresult, "getvalue", pgresult_getvalue, 2);
	rb_define_method(rb_cPGresult, "getisnull", pgresult_getisnull, 2);
	rb_define_method(rb_cPGresult, "getlength", pgresult_getlength, 2);
	rb_define_method(rb_cPGresult, "nparams", pgresult_nparams, 0);
	rb_define_method(rb_cPGresult, "paramtype", pgresult_paramtype, 1);
	rb_define_method(rb_cPGresult, "cmd_status", pgresult_cmd_status, 0);
	rb_define_method(rb_cPGresult, "cmd_tuples", pgresult_cmd_tuples, 0);
	rb_define_alias(rb_cPGresult, "cmdtuples", "cmd_tuples");
	rb_define_method(rb_cPGresult, "oid_value", pgresult_oid_value, 0);

	/******     PG::Result INSTANCE METHODS: other     ******/
	rb_define_method(rb_cPGresult, "[]", pgresult_aref, 1);
	rb_define_method(rb_cPGresult, "each", pgresult_each, 0);
	rb_define_method(rb_cPGresult, "fields", pgresult_fields, 0);
	rb_define_method(rb_cPGresult, "values", pgresult_values, 0);
	rb_define_method(rb_cPGresult, "column_values", pgresult_column_values, 1);
	rb_define_method(rb_cPGresult, "field_values", pgresult_field_values, 1);
}


