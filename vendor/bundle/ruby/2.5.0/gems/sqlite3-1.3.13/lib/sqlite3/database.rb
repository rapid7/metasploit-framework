require 'sqlite3/constants'
require 'sqlite3/errors'
require 'sqlite3/pragmas'
require 'sqlite3/statement'
require 'sqlite3/translator'
require 'sqlite3/value'

module SQLite3

  # The Database class encapsulates a single connection to a SQLite3 database.
  # Its usage is very straightforward:
  #
  #   require 'sqlite3'
  #
  #   SQLite3::Database.new( "data.db" ) do |db|
  #     db.execute( "select * from table" ) do |row|
  #       p row
  #     end
  #   end
  #
  # It wraps the lower-level methods provides by the selected driver, and
  # includes the Pragmas module for access to various pragma convenience
  # methods.
  #
  # The Database class provides type translation services as well, by which
  # the SQLite3 data types (which are all represented as strings) may be
  # converted into their corresponding types (as defined in the schemas
  # for their tables). This translation only occurs when querying data from
  # the database--insertions and updates are all still typeless.
  #
  # Furthermore, the Database class has been designed to work well with the
  # ArrayFields module from Ara Howard. If you require the ArrayFields
  # module before performing a query, and if you have not enabled results as
  # hashes, then the results will all be indexible by field name.
  class Database
    attr_reader :collations

    include Pragmas

    class << self

      alias :open :new

      # Quotes the given string, making it safe to use in an SQL statement.
      # It replaces all instances of the single-quote character with two
      # single-quote characters. The modified string is returned.
      def quote( string )
        string.gsub( /'/, "''" )
      end

    end

    # A boolean that indicates whether rows in result sets should be returned
    # as hashes or not. By default, rows are returned as arrays.
    attr_accessor :results_as_hash

    def type_translation= value # :nodoc:
      warn(<<-eowarn) if $VERBOSE
#{caller[0]} is calling SQLite3::Database#type_translation=
SQLite3::Database#type_translation= is deprecated and will be removed
in version 2.0.0.
      eowarn
      @type_translation = value
    end
    attr_reader :type_translation # :nodoc:

    # Return the type translator employed by this database instance. Each
    # database instance has its own type translator; this allows for different
    # type handlers to be installed in each instance without affecting other
    # instances. Furthermore, the translators are instantiated lazily, so that
    # if a database does not use type translation, it will not be burdened by
    # the overhead of a useless type translator. (See the Translator class.)
    def translator
      @translator ||= Translator.new
    end

    # Installs (or removes) a block that will be invoked for every access
    # to the database. If the block returns 0 (or +nil+), the statement
    # is allowed to proceed. Returning 1 causes an authorization error to
    # occur, and returning 2 causes the access to be silently denied.
    def authorizer( &block )
      self.authorizer = block
    end

    # Returns a Statement object representing the given SQL. This does not
    # execute the statement; it merely prepares the statement for execution.
    #
    # The Statement can then be executed using Statement#execute.
    #
    def prepare sql
      stmt = SQLite3::Statement.new( self, sql )
      return stmt unless block_given?

      begin
        yield stmt
      ensure
        stmt.close unless stmt.closed?
      end
    end

    # Returns the filename for the database named +db_name+.  +db_name+ defaults
    # to "main".  Main return `nil` or an empty string if the database is
    # temporary or in-memory.
    def filename db_name = 'main'
      db_filename db_name
    end

    # Executes the given SQL statement. If additional parameters are given,
    # they are treated as bind variables, and are bound to the placeholders in
    # the query.
    #
    # Note that if any of the values passed to this are hashes, then the
    # key/value pairs are each bound separately, with the key being used as
    # the name of the placeholder to bind the value to.
    #
    # The block is optional. If given, it will be invoked for each row returned
    # by the query. Otherwise, any results are accumulated into an array and
    # returned wholesale.
    #
    # See also #execute2, #query, and #execute_batch for additional ways of
    # executing statements.
    def execute sql, bind_vars = [], *args, &block
      if bind_vars.nil? || !args.empty?
        if args.empty?
          bind_vars = []
        else
          bind_vars = [bind_vars] + args
        end

        warn(<<-eowarn) if $VERBOSE
#{caller[0]} is calling SQLite3::Database#execute with nil or multiple bind params
without using an array.  Please switch to passing bind parameters as an array.
Support for bind parameters as *args will be removed in 2.0.0.
        eowarn
      end

      prepare( sql ) do |stmt|
        stmt.bind_params(bind_vars)
        columns = stmt.columns
        stmt    = ResultSet.new(self, stmt).to_a if type_translation

        if block_given?
          stmt.each do |row|
            if @results_as_hash
              yield type_translation ? row : ordered_map_for(columns, row)
            else
              yield row
            end
          end
        else
          if @results_as_hash
            stmt.map { |row|
              type_translation ? row : ordered_map_for(columns, row)
            }
          else
            stmt.to_a
          end
        end
      end
    end

    # Executes the given SQL statement, exactly as with #execute. However, the
    # first row returned (either via the block, or in the returned array) is
    # always the names of the columns. Subsequent rows correspond to the data
    # from the result set.
    #
    # Thus, even if the query itself returns no rows, this method will always
    # return at least one row--the names of the columns.
    #
    # See also #execute, #query, and #execute_batch for additional ways of
    # executing statements.
    def execute2( sql, *bind_vars )
      prepare( sql ) do |stmt|
        result = stmt.execute( *bind_vars )
        if block_given?
          yield stmt.columns
          result.each { |row| yield row }
        else
          return result.inject( [ stmt.columns ] ) { |arr,row|
            arr << row; arr }
        end
      end
    end

    # Executes all SQL statements in the given string. By contrast, the other
    # means of executing queries will only execute the first statement in the
    # string, ignoring all subsequent statements. This will execute each one
    # in turn. The same bind parameters, if given, will be applied to each
    # statement.
    #
    # This always returns +nil+, making it unsuitable for queries that return
    # rows.
    def execute_batch( sql, bind_vars = [], *args )
      # FIXME: remove this stuff later
      unless [Array, Hash].include?(bind_vars.class)
        bind_vars = [bind_vars]
        warn(<<-eowarn) if $VERBOSE
#{caller[0]} is calling SQLite3::Database#execute_batch with bind parameters
that are not a list of a hash.  Please switch to passing bind parameters as an
array or hash. Support for this behavior will be removed in version 2.0.0.
        eowarn
      end

      # FIXME: remove this stuff later
      if bind_vars.nil? || !args.empty?
        if args.empty?
          bind_vars = []
        else
          bind_vars = [nil] + args
        end

        warn(<<-eowarn) if $VERBOSE
#{caller[0]} is calling SQLite3::Database#execute_batch with nil or multiple bind params
without using an array.  Please switch to passing bind parameters as an array.
Support for this behavior will be removed in version 2.0.0.
        eowarn
      end

      sql = sql.strip
      until sql.empty? do
        prepare( sql ) do |stmt|
          unless stmt.closed?
            # FIXME: this should probably use sqlite3's api for batch execution
            # This implementation requires stepping over the results.
            if bind_vars.length == stmt.bind_parameter_count
              stmt.bind_params(bind_vars)
            end
            stmt.step
          end
          sql = stmt.remainder.strip
        end
      end
      # FIXME: we should not return `nil` as a success return value
      nil
    end

    # This is a convenience method for creating a statement, binding
    # paramters to it, and calling execute:
    #
    #   result = db.query( "select * from foo where a=?", [5])
    #   # is the same as
    #   result = db.prepare( "select * from foo where a=?" ).execute( 5 )
    #
    # You must be sure to call +close+ on the ResultSet instance that is
    # returned, or you could have problems with locks on the table. If called
    # with a block, +close+ will be invoked implicitly when the block
    # terminates.
    def query( sql, bind_vars = [], *args )

      if bind_vars.nil? || !args.empty?
        if args.empty?
          bind_vars = []
        else
          bind_vars = [bind_vars] + args
        end

        warn(<<-eowarn) if $VERBOSE
#{caller[0]} is calling SQLite3::Database#query with nil or multiple bind params
without using an array.  Please switch to passing bind parameters as an array.
Support for this will be removed in version 2.0.0.
        eowarn
      end

      result = prepare( sql ).execute( bind_vars )
      if block_given?
        begin
          yield result
        ensure
          result.close
        end
      else
        return result
      end
    end

    # A convenience method for obtaining the first row of a result set, and
    # discarding all others. It is otherwise identical to #execute.
    #
    # See also #get_first_value.
    def get_first_row( sql, *bind_vars )
      execute( sql, *bind_vars ).first
    end

    # A convenience method for obtaining the first value of the first row of a
    # result set, and discarding all other values and rows. It is otherwise
    # identical to #execute.
    #
    # See also #get_first_row.
    def get_first_value( sql, *bind_vars )
      execute( sql, *bind_vars ) { |row| return row[0] }
      nil
    end

    alias :busy_timeout :busy_timeout=

    # Creates a new function for use in SQL statements. It will be added as
    # +name+, with the given +arity+. (For variable arity functions, use
    # -1 for the arity.)
    #
    # The block should accept at least one parameter--the FunctionProxy
    # instance that wraps this function invocation--and any other
    # arguments it needs (up to its arity).
    #
    # The block does not return a value directly. Instead, it will invoke
    # the FunctionProxy#result= method on the +func+ parameter and
    # indicate the return value that way.
    #
    # Example:
    #
    #   db.create_function( "maim", 1 ) do |func, value|
    #     if value.nil?
    #       func.result = nil
    #     else
    #       func.result = value.split(//).sort.join
    #     end
    #   end
    #
    #   puts db.get_first_value( "select maim(name) from table" )
    def create_function name, arity, text_rep=Constants::TextRep::ANY, &block
      define_function(name) do |*args|
        fp = FunctionProxy.new
        block.call(fp, *args)
        fp.result
      end
      self
    end

    # Creates a new aggregate function for use in SQL statements. Aggregate
    # functions are functions that apply over every row in the result set,
    # instead of over just a single row. (A very common aggregate function
    # is the "count" function, for determining the number of rows that match
    # a query.)
    #
    # The new function will be added as +name+, with the given +arity+. (For
    # variable arity functions, use -1 for the arity.)
    #
    # The +step+ parameter must be a proc object that accepts as its first
    # parameter a FunctionProxy instance (representing the function
    # invocation), with any subsequent parameters (up to the function's arity).
    # The +step+ callback will be invoked once for each row of the result set.
    #
    # The +finalize+ parameter must be a +proc+ object that accepts only a
    # single parameter, the FunctionProxy instance representing the current
    # function invocation. It should invoke FunctionProxy#result= to
    # store the result of the function.
    #
    # Example:
    #
    #   db.create_aggregate( "lengths", 1 ) do
    #     step do |func, value|
    #       func[ :total ] ||= 0
    #       func[ :total ] += ( value ? value.length : 0 )
    #     end
    #
    #     finalize do |func|
    #       func.result = func[ :total ] || 0
    #     end
    #   end
    #
    #   puts db.get_first_value( "select lengths(name) from table" )
    #
    # See also #create_aggregate_handler for a more object-oriented approach to
    # aggregate functions.
    def create_aggregate( name, arity, step=nil, finalize=nil,
      text_rep=Constants::TextRep::ANY, &block )

      factory = Class.new do
        def self.step( &block )
          define_method(:step, &block)
        end

        def self.finalize( &block )
          define_method(:finalize, &block)
        end
      end

      if block_given?
        factory.instance_eval(&block)
      else
        factory.class_eval do
          define_method(:step, step)
          define_method(:finalize, finalize)
        end
      end

      proxy = factory.new
      proxy.extend(Module.new {
        attr_accessor :ctx

        def step( *args )
          super(@ctx, *args)
        end

        def finalize
          super(@ctx)
          result = @ctx.result
          @ctx = FunctionProxy.new
          result
        end
      })
      proxy.ctx = FunctionProxy.new
      define_aggregator(name, proxy)
    end

    # This is another approach to creating an aggregate function (see
    # #create_aggregate). Instead of explicitly specifying the name,
    # callbacks, arity, and type, you specify a factory object
    # (the "handler") that knows how to obtain all of that information. The
    # handler should respond to the following messages:
    #
    # +arity+:: corresponds to the +arity+ parameter of #create_aggregate. This
    #           message is optional, and if the handler does not respond to it,
    #           the function will have an arity of -1.
    # +name+:: this is the name of the function. The handler _must_ implement
    #          this message.
    # +new+:: this must be implemented by the handler. It should return a new
    #         instance of the object that will handle a specific invocation of
    #         the function.
    #
    # The handler instance (the object returned by the +new+ message, described
    # above), must respond to the following messages:
    #
    # +step+:: this is the method that will be called for each step of the
    #          aggregate function's evaluation. It should implement the same
    #          signature as the +step+ callback for #create_aggregate.
    # +finalize+:: this is the method that will be called to finalize the
    #              aggregate function's evaluation. It should implement the
    #              same signature as the +finalize+ callback for
    #              #create_aggregate.
    #
    # Example:
    #
    #   class LengthsAggregateHandler
    #     def self.arity; 1; end
    #     def self.name; 'lengths'; end
    #
    #     def initialize
    #       @total = 0
    #     end
    #
    #     def step( ctx, name )
    #       @total += ( name ? name.length : 0 )
    #     end
    #
    #     def finalize( ctx )
    #       ctx.result = @total
    #     end
    #   end
    #
    #   db.create_aggregate_handler( LengthsAggregateHandler )
    #   puts db.get_first_value( "select lengths(name) from A" )
    def create_aggregate_handler( handler )
      proxy = Class.new do
        def initialize klass
          @klass = klass
          @fp    = FunctionProxy.new
        end

        def step( *args )
          instance.step(@fp, *args)
        end

        def finalize
          instance.finalize @fp
          @instance = nil
          @fp.result
        end

        private

        def instance
          @instance ||= @klass.new
        end
      end
      define_aggregator(handler.name, proxy.new(handler))
      self
    end

    # Begins a new transaction. Note that nested transactions are not allowed
    # by SQLite, so attempting to nest a transaction will result in a runtime
    # exception.
    #
    # The +mode+ parameter may be either <tt>:deferred</tt> (the default),
    # <tt>:immediate</tt>, or <tt>:exclusive</tt>.
    #
    # If a block is given, the database instance is yielded to it, and the
    # transaction is committed when the block terminates. If the block
    # raises an exception, a rollback will be performed instead. Note that if
    # a block is given, #commit and #rollback should never be called
    # explicitly or you'll get an error when the block terminates.
    #
    # If a block is not given, it is the caller's responsibility to end the
    # transaction explicitly, either by calling #commit, or by calling
    # #rollback.
    def transaction( mode = :deferred )
      execute "begin #{mode.to_s} transaction"

      if block_given?
        abort = false
        begin
          yield self
        rescue ::Object
          abort = true
          raise
        ensure
          abort and rollback or commit
        end
      end

      true
    end

    # Commits the current transaction. If there is no current transaction,
    # this will cause an error to be raised. This returns +true+, in order
    # to allow it to be used in idioms like
    # <tt>abort? and rollback or commit</tt>.
    def commit
      execute "commit transaction"
      true
    end

    # Rolls the current transaction back. If there is no current transaction,
    # this will cause an error to be raised. This returns +true+, in order
    # to allow it to be used in idioms like
    # <tt>abort? and rollback or commit</tt>.
    def rollback
      execute "rollback transaction"
      true
    end

    # Returns +true+ if the database has been open in readonly mode
    # A helper to check before performing any operation
    def readonly?
      @readonly
    end

    # A helper class for dealing with custom functions (see #create_function,
    # #create_aggregate, and #create_aggregate_handler). It encapsulates the
    # opaque function object that represents the current invocation. It also
    # provides more convenient access to the API functions that operate on
    # the function object.
    #
    # This class will almost _always_ be instantiated indirectly, by working
    # with the create methods mentioned above.
    class FunctionProxy
      attr_accessor :result

      # Create a new FunctionProxy that encapsulates the given +func+ object.
      # If context is non-nil, the functions context will be set to that. If
      # it is non-nil, it must quack like a Hash. If it is nil, then none of
      # the context functions will be available.
      def initialize
        @result   = nil
        @context  = {}
      end

      # Set the result of the function to the given error message.
      # The function will then return that error.
      def set_error( error )
        @driver.result_error( @func, error.to_s, -1 )
      end

      # (Only available to aggregate functions.) Returns the number of rows
      # that the aggregate has processed so far. This will include the current
      # row, and so will always return at least 1.
      def count
        @driver.aggregate_count( @func )
      end

      # Returns the value with the given key from the context. This is only
      # available to aggregate functions.
      def []( key )
        @context[ key ]
      end

      # Sets the value with the given key in the context. This is only
      # available to aggregate functions.
      def []=( key, value )
        @context[ key ] = value
      end
    end

    private

    def ordered_map_for columns, row
      h = Hash[*columns.zip(row).flatten]
      row.each_with_index { |r, i| h[i] = r }
      h
    end
  end
end
