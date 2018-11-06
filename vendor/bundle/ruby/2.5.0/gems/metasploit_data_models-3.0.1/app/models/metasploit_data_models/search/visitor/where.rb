# Generates AREL to pass to `ActiveRecord::Relation#where` from a `Metasploit::Model::Search::Query`.
class MetasploitDataModels::Search::Visitor::Where
  include Metasploit::Model::Visitation::Visit

  #
  # CONSTANTS
  #

  # `Metasploit::Model::Search::Operation::Base` subclasses that check their value with the equality operator in
  # AREL
  EQUALITY_OPERATION_CLASS_NAMES = [
      'Metasploit::Model::Search::Operation::Boolean',
      'Metasploit::Model::Search::Operation::Date',
      'Metasploit::Model::Search::Operation::Integer',
      'Metasploit::Model::Search::Operation::Set'
  ]

  #
  # Visitor
  #

  visit 'Metasploit::Model::Search::Group::Base',
        'Metasploit::Model::Search::Operation::Group::Base' do |parent|
    method = method_visitor.visit parent

    children_arel = parent.children.collect { |child|
      visit child
    }

    children_arel.inject { |group_arel, child_arel|
      group_arel.send(method, child_arel)
    }
  end

  visit(*EQUALITY_OPERATION_CLASS_NAMES) do |operation|
    attribute = attribute_visitor.visit operation.operator

    attribute.eq(operation.value)
  end

  visit 'Metasploit::Model::Search::Operation::Association' do |operation|
    visit operation.source_operation
  end

  visit 'Metasploit::Model::Search::Operation::String' do |operation|
    attribute = attribute_visitor.visit operation.operator
    match_value = "%#{operation.value}%"

    attribute.matches(match_value)
  end

  visit 'MetasploitDataModels::IPAddress::CIDR' do |cidr|
    cast_to_inet "#{cidr.address}/#{cidr.prefix_length}"
  end

  visit 'MetasploitDataModels::IPAddress::Range' do |ip_address_range|
    range = ip_address_range.value

    begin_node = visit range.begin
    end_node = visit range.end

    # AND nodes should be created with a list
    Arel::Nodes::And.new([begin_node, end_node])
  end

  visit 'MetasploitDataModels::IPAddress::V4::Single' do |ip_address|
    cast_to_inet(ip_address.to_s)
  end

  visit 'MetasploitDataModels::Search::Operation::IPAddress' do |operation|
    attribute = attribute_visitor.visit operation.operator
    value = operation.value
    value_node = visit value

    case value
      when MetasploitDataModels::IPAddress::CIDR
        Arel::Nodes::InfixOperation.new(
            '<<',
            attribute,
            value_node
        )
      when MetasploitDataModels::IPAddress::Range
        Arel::Nodes::Between.new(attribute, value_node)
      when MetasploitDataModels::IPAddress::V4::Single
        Arel::Nodes::Equality.new(attribute, value_node)
      else
        raise TypeError, "Don't know how to handle #{value.class}"
    end
  end

  visit 'MetasploitDataModels::Search::Operation::Port::Range' do |range_operation|
    attribute = attribute_visitor.visit range_operation.operator

    attribute.in(range_operation.value)
  end

  #
  # Methods
  #

  # Visitor for `Metasploit::Model::Search::Operator::Base` subclasses to generate `Arel::Attributes::Attribute`.
  #
  # @return [MetasploitDataModels::Search::Visitor::Attribute]
  def attribute_visitor
    @attribute_visitor ||= MetasploitDataModels::Search::Visitor::Attribute.new
  end

  # Visitor for `Metasploit::Model::Search::Group::Base` subclasses to generate equivalent AREL node methods.
  #
  # @return [MetasploitDataModels::Search::Visitor::Method]
  def method_visitor
    @method_visitor ||= MetasploitDataModels::Search::Visitor::Method.new
  end

  private

  # Casts a literal string to INET in AREL.
  #
  # @return [Arel::Nodes::NamedFunction]
  def cast_to_inet(string)
    cast_argument = Arel::Nodes::As.new(Arel::Nodes.build_quoted(string), Arel::Nodes::SqlLiteral.new('INET'))
    Arel::Nodes::NamedFunction.new('CAST', [cast_argument])
  end

  public

  Metasploit::Concern.run(self)
end
