module Msf::Util::EXE::OSX::Common
  include Msf::Util::EXE::Common
  def self.included(base)
    base.extend(ClassMethods)
  end

  module ClassMethods
    def to_executable_with_template(template_name, framework, code, opts = {})
      # Allow the user to specify their own template
      set_template_default(opts, template_name)

      mo = self.get_file_contents(opts[:template])
      bo = self.find_payload_tag(mo, "Invalid OSX ArmLE Mach-O template: missing \"PAYLOAD:\" tag")
      mo[bo, code.length] = code
      mo
    end
  end
  class << self
    include ClassMethods
  end
end