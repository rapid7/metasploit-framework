# Search operation on an attribute that has a `Set<String>` for acceptable
# {Metasploit::Model::Search::Operation::Base values}.
class Metasploit::Model::Search::Operation::Set::String < Metasploit::Model::Search::Operation::Set
  include Metasploit::Model::Search::Operation::Value::String
end