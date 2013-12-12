# Adds support for declaring {ClassMethods#subcommands} on this command.
module Metasploit::Framework::Command::Parent
  extend ActiveSupport::Concern

  included do
    include ActiveModel::Validations

    validates :subcommand_name,
              inclusion: {
                  in: ->(command){
                    command.class.subcommand_names
                  }
              }
  end

  module ClassMethods
    attr_writer :default_subcommand_name

    def default_subcommand_name
      @default_subcommand_name ||= :help
    end

    # @param name [Symbol] name of the subcommand.  This should match the relative name of a class under this
    #   class.
    # @param options [Hash{Symbol => Boolean}]
    # @option options [Boolean] :default (false) Whether this is the default command.
    def subcommand(name, options={})
      if options.fetch(:default, false)
        self.default_subcommand_name = name
      end

      subcommand_names << name
    end

    def subcommand_names
      @subcommand_names ||= []
    end

    def subcommand_class_by_name
      @subcommand_class_by_name ||= subcommand_names.each_with_object({}) { |name, subcommand_class_by_name|
        subcommand_class_name = "#{self.name}::#{name.to_s.camelize}"
        subcommand_class = subcommand_class_name.constantize

        subcommand_class_by_name[name] = subcommand_class
      }
    end
  end

  #
  # Attributes
  #

  # @!attribute [rw] subcommand_name
  #   Name of the subcommand to run.
  #
  #   @return [Symbol]
  attr_writer :subcommand_name

  #
  # Instance Methods
  #

  def blank_tab_completions
    completions = []

    # if there are no words, then the user can either ask for help or use the subcommand as usual
    if words.empty?
      completions += [
          '-h',
          '--help'
      ]
    end

    completions += subcommand.blank_tab_completions

    completions
  end

  delegate :partial_tab_completions,
           to: :subcommand

  def subcommand_name
    unless instance_variable_defined? :@subcommand_name
      parse_words

      @subcommand_name ||= self.class.default_subcommand_name
    end

    @subcommand_name
  end

  private

  # Runs the {#subcommand}.
  #
  # @return [void]
  def run_with_valid
    subcommand.run
  end

  # Subcommand class instance from {#subcommand_by_name} with {#subcommand_name}.
  #
  # @return [Metasploit::Framework::Command::Child]
  # @return [nil] if {#subcommand_name} is invalid.
  def subcommand
    subcommand_by_name[subcommand_name]
  end

  # Instance of {ClassMethods#subcommand_class_by_name subcommand class} by name so that options parsed from words can
  # be assigned to the correct subcommand.
  #
  # @return [Hash{Symbol => Metasploit::Framework::Command::Child}]
  def subcommand_by_name
    @subcommand_by_name ||= Hash.new { |hash, name|
      subcommand_class = self.class.subcommand_class_by_name[name]

      if subcommand_class
        subcommand = subcommand_class.new(parent: self)
      else
        subcommand = nil
      end

      hash[name] = subcommand
    }
  end
end