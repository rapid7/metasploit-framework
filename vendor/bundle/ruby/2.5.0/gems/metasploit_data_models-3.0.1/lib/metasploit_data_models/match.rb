# Namespace for {MetasploitDataModels::Match::Parent#match_child dispatching} to
# {MetasploitDataModels::Match::Child#match children based on if their Regexp matches}.
module MetasploitDataModels::Match
  extend ActiveSupport::Autoload

  autoload :Child
  autoload :Parent
end
