# frozen_string_literal: true
attr_reader :contents

def init
  if object
    type = object.root? ? :module : object.type
    sections :header, [T(type)]
  else
    sections :header, [:contents]
  end
end

def header
  tidy erb(:header)
end
