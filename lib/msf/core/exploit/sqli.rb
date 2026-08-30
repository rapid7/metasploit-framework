module Msf
  #
  # This mixin provides helpers to perform SQL injection
  # - provides a level of abstraction for common queries, for example, querying the table names
  # - implements blind and time-based SQL injection in a reusable manner
  # - Highly extendable (user can run any code to perform the requests, encode payloads and parse results)
  #
  module Exploit::SQLi
    def initialize(info = {})
      super
      register_advanced_options(
        [
          OptFloat.new('SqliDelay', [ false, 'The delay to sleep on time-based blind SQL injections', 1.0 ])
        ]
      )
    end

    #
    # Creates an SQL injection object, this is the method module writers should use
    # @param dbms [Class] The SQL injection class you intend to use
    # @param opts [Hash] The options to use with this SQL injection
    # @param query_proc [Proc] The proc that takes an SQL payload as a parameter, and queries the server
    # @return [Object] an instance of dbms
    #
    def create_sqli(dbms:, opts: {}, &query_proc)
      raise ArgumentError, 'Invalid dbms class' unless dbms.is_a?(Class) && dbms.ancestors.include?(Msf::Exploit::SQLi::Common)

      dbms.new(datastore, framework, user_output, opts, &query_proc)
    end
  end
end
