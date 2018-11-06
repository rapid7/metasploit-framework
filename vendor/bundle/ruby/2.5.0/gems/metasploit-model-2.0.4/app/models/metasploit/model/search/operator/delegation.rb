# An operator that delegates to another operator(s).
class Metasploit::Model::Search::Operator::Delegation < Metasploit::Model::Search::Operator::Base
  #
  # Methods
  #

  # @note Can't be called `name` because it would alias `Class#name`.
  #
  # Name of this operator.
  #
  # @return [String]
  def self.operator_name
    @operator_name ||= name.demodulize.underscore.to_sym
  end

  # Name of operator.
  #
  # @return (see operator_name)
  def name
    @name ||= self.class.operator_name
  end

  protected

  # Finds operator with the given name on {Metasploit::Model::Search::Operator::Base#klass}.
  #
  # @param formatted_operator [#to_sym] Name of operator.
  # @return [Metasploit::Model::Search::Operator::Base] if operator with `formatted_operator` for
  #   {Metasploit::Model::Search::Operator::Base#name} exists for {Metasploit::Model::Search::Operator::Base#klass}.
  def operator(formatted_operator)
    name = formatted_operator.to_sym
    operator = klass.search_operator_by_name[name]

    unless operator
      raise ArgumentError, "No operator with name #{name.inspect} on #{klass}"
    end

    operator
  end
end