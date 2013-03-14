# encoding: utf-8
module Mail

  # Field List class provides an enhanced array that keeps a list of 
  # email fields in order.  And allows you to insert new fields without
  # having to worry about the order they will appear in.
  class FieldList < Array

    include Enumerable

    def <<( new_field )
      current_entry = self.rindex(new_field)
      if current_entry
        self.insert((current_entry + 1), new_field)
      else
        insert_idx = -1
        self.each_with_index do |item, idx|
          case item <=> new_field
          when -1
            next
          when 0
            next
          when 1
            insert_idx = idx
            break
          end
        end
        insert(insert_idx, new_field)
      end
    end
    
  end
end