# -*- coding: binary -*-

module Msf
  class Post
    module Linux
      module Wsl
        include ::Msf::Post::Linux::Kernel
        #
        # Returns a boolean if the kernel includes WSL indicators
        #
        def wsl?
          kernel_release.include?('-Microsoft')
        end
      end
    end
  end
end
