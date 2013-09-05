# -*- coding: binary -*-
require_relative "regf"
require_relative "nodekey"

module Rex
module Registry

class Hive
  attr_accessor :root_key, :hive_regf, :hive_name

  def initialize(hivepath)

    hive_blob = open(hivepath, "rb") { |io| io.read }

    @hive_regf = RegfBlock.new(hive_blob)
    return nil if !@hive_regf.root_key_offset

    @root_key = NodeKey.new(hive_blob, 0x1000 + @hive_regf.root_key_offset)
    return nil if !@root_key.lf_record

    keys = []
    root_key.lf_record.children.each do |key|
      keys << key.name
    end

    if keys.include? "LastKnownGoodRecovery"
      @hive_name = "SYSTEM"
    elsif keys.include? "Microsoft"
      @hive_name = "SOFTWARE"
    elsif keys.include? "Environment"
      @hive_name = "NTUSER.DAT"
    elsif keys.include? "SAM"
      @hive_name = "SAM"
    elsif keys.include? "Policy"
      @hive_name = "SECURITY"
    else
      @hive_name = "UNKNOWN"
    end

  end

  def relative_query(path)

    if path == "" || path == "\\"
      return @root_key
    end

    current_child = nil
    paths = path.split("\\")

    return if !@root_key.lf_record

    @root_key.lf_record.children.each do |child|
      next if child.name.downcase != paths[1].downcase

      current_child = child

      if paths.length == 2
        current_child.full_path = path
        return current_child
      end

      2.upto(paths.length) do |i|

        if i == paths.length
          current_child.full_path = path
          return current_child
        else
          if current_child.lf_record && current_child.lf_record.children
            current_child.lf_record.children.each do |c|
              next if c.name.downcase != paths[i].downcase

              current_child = c

              break
            end
          end
        end
      end
    end

    return if !current_child

    current_child.full_path = path
    return current_child
    end

    def value_query(path)
      if path == "" || path == "\\"
      return nil
    end

    paths = path.split("\\")

    return if !@root_key.lf_record

    @root_key.lf_record.children.each do |root_child|
      next if root_child.name.downcase != paths[1].downcase

      current_child = root_child

      if paths.length == 2
        return nil
      end

      2.upto(paths.length - 1) do |i|
        next if !current_child.lf_record

        current_child.lf_record.children.each do |c|
          next if c.name != paths[i]
          current_child = c

          break
        end
      end

      if !current_child.value_list || current_child.value_list.values.length == 0
        return nil
      end

      current_child.value_list.values.each do |value|
        next if value.name.downcase != paths[paths.length - 1].downcase

        value.full_path = path
        return value
      end
    end
  end
end

end
end
