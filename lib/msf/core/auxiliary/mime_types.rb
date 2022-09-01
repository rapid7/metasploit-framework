# -*- coding: binary -*-
require 'action_dispatch/http/mime_type'

module Msf

module Auxiliary::MimeTypes

  def mime_lookup_by_extension(extension)
    return 'application/octet-stream' if extension.nil? or extension.empty?
    if extension.starts_with? '.'
      extension.delete!('.')
    end
    mtype = Mime::Type.lookup_by_extension(extension)
    mtype = mime_yaml_lookup(extension) if mtype.nil?
    mtype = "application/#{extension}" if mtype.nil?
    return mtype
  end

  def mime_yaml_lookup(extension)
    mime_load_extension_map unless @extension_map
    return @extension_map[extension] if @extension_map[extension]
    return nil
  end

  def mime_load_extension_map
    path = File.join( Msf::Config.data_directory, "mime.yml")
    @extension_map = YAML.load_file(path)
  end

end
end


