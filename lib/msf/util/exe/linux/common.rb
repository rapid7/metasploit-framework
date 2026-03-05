module Msf::Util::EXE::Linux::Common
  include Msf::Util::EXE::Common
  def self.included(base)
    base.extend(ClassMethods)
  end

  module ClassMethods
  end

  class << self
    include ClassMethods
  end
end
