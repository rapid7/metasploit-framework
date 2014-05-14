# Top-level namespace that is shared between {Metasploit::Framework
# metasploit-framework} and pro, which uses Metasploit::Pro.
module Metasploit
  # Supports Rails and Rails::Engine like access to metasploit-framework so it
  # works in compatible manner with activerecord's rake tasks and other
  # railties.
  module Framework
    # Returns the root of the metasploit-framework project.  Use in place of
    # `Rails.root`.
    #
    # @return [Pathname]
    def self.root
      unless instance_variable_defined? :@root
        pathname = Pathname.new(__FILE__)
        @root = pathname.parent.parent.parent
      end

      @root
    end
  end
end