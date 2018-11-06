# -*- coding: binary -*-

# Rex::Struct2
module Rex
module Struct2

class CStructTemplate

  require 'rex/struct2/c_struct'

  attr_reader  :template, :template_create_restraints, :template_apply_restraint
  attr_writer  :template, :template_create_restraints, :template_apply_restraint

  def initialize(*tem)
    self.template = tem
    self.template_create_restraints = [ ]
    self.template_apply_restraint = [ ]
  end

  def create_restraints(*ress)
    self.template_create_restraints = ress
    return self
  end

  def apply_restraint(*ress)
    self.template_apply_restraint = ress
    return self
  end

  def make_struct
    Rex::Struct2::CStruct.new(*self.template).
      create_restraints(*self.template_create_restraints).
      apply_restraint(*self.template_apply_restraint)
  end
end

# end Rex::Struct2
end
end
