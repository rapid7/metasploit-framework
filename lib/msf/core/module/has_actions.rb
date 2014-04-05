# -*- coding: binary -*-
require 'msf/core/module/auxiliary_action'

module Msf::Module::HasActions
  def initialize(info={})
    super
    self.actions = Rex::Transformer.transform(
      info['Actions'], Array,
      [ Msf::Module::AuxiliaryAction ], 'AuxiliaryAction'
    )

    self.passive = (info['Passive'] and info['Passive'] == true) || false
    self.default_action = info['DefaultAction']
    self.passive_actions = info['PassiveActions'] || []
  end

  def action
    sa = datastore['ACTION']
    return find_action(default_action) if not sa
    return find_action(sa)
  end

  def find_action(name)
    return nil if not name
    actions.each do |a|
      return a if a.name == name
    end
    return nil
  end

  #
  # Returns a boolean indicating whether this module should be run passively
  #
  def passive?
    act = action()
    return passive_action?(act.name) if act
    return self.passive
  end

  #
  # Returns a boolean indicating whether this specific action should be run passively
  #
  def passive_action?(name)
    passive_actions.include?(name)
  end

  #
  # Allow access to the hash table of actions and the string containing
  # the default action
  #
  attr_reader :actions, :default_action, :passive, :passive_actions

protected
  attr_writer :actions, :default_action, :passive, :passive_actions
end
