module Zip
  class StreamableDirectory < Entry
    def initialize(zipfile, entry, srcPath = nil, permissionInt = nil)
      super(zipfile, entry)

      @ftype = :directory
      entry.get_extra_attributes_from_path(srcPath) if srcPath
      @unix_perms = permissionInt if permissionInt
    end
  end
end

# Copyright (C) 2002, 2003 Thomas Sondergaard
# rubyzip is free software; you can redistribute it and/or
# modify it under the terms of the ruby license.
