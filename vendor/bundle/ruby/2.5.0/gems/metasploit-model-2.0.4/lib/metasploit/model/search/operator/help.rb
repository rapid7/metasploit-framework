# This allows the help to be looked up using `I18n`, and for the
# help to be customized based on the following criteria:
#
# `klass` on which the operator is declared, including any `Module#ancestors` and the operator `name`
#
#     # config/locales/<lang>.yml
#     <lang>:
#       <klass.i18n_scope>:
#         ancestors:
#           <klass_ancestor.model_name.i18n_key>:
#             search:
#               operator:
#                 names:
#                   <name>:
#                     help: "Help for searching <name> on <klass>"
#
# `class` of the operator, including any `Module#ancestors` and the operator `name`
#
#     # config/locales/<lang>.yml
#     <lang>:
#       <operator.class.i18n_scope>:
#         search:
#           operator:
#             ancestors:
#               <operator_class_ancestor.model_name.i18n_key>:
#                 <name>:
#                   help: "Help for searching <name> using <operator.class>"
#
# `class` of the operator, including any `Module#ancestors` without the operator `name`
#
#     # config/locales/<lang>.yml
#     <lang>:
#       <operator.class.i18n_scope>:
#         search:
#           operator:
#             ancestors:
#               <operator_class_ancestor.model_name.i18n_key>:
#                 help: "Help for searching using <operator.class>"
#
module Metasploit::Model::Search::Operator::Help
  # @note This uses I18n.translate along with {Metasploit::Model::Translation#search_i18n_scope},
  #   the value is not cached to support changing the I18n.locale and getting the correct help message for that
  #   locale.
  #
  # The help for this operator.
  #
  # @see https://github.com/rails/rails/blob/6c2810b8ed692004dca43e554982cdfdb8517b80/activemodel/lib/active_model/errors.rb#L408-L435
  def help
    defaults = []
    klass_i18n_scope = klass.i18n_scope

    klass.lookup_ancestors.each do |ancestor|
      # a specific operator for a given Class#ancestors member
      defaults << :"#{klass_i18n_scope}.ancestors.#{ancestor.model_name.i18n_key}.search.operator.names.#{name}.help"
    end

    operator_class = self.class
    operator_i18n_scope = operator_class.i18n_scope

    operator_class.lookup_ancestors.each do |ancestor|
      # a specific name for a given operator
      defaults << :"#{operator_i18n_scope}.search.operator.ancestors.#{ancestor.model_name.i18n_key}.names.#{name}.help"
      # a specific operator class
      defaults << :"#{operator_i18n_scope}.search.operator.ancestors.#{ancestor.model_name.i18n_key}.help"
    end

    # use first default as key because it is most specific default, that is closest to klass.
    key = defaults.shift
    options = {
        default: defaults,
        model: klass.model_name.human,
        name: name
    }

    ::I18n.translate(key, options)
  end
end
