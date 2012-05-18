module Liquid
  class TableRow < Block
    Syntax = /(\w+)\s+in\s+(#{QuotedFragment}+)/

    def initialize(tag_name, markup, tokens)
      if markup =~ Syntax
        @variable_name = $1
        @collection_name = $2
        @attributes = {}
        markup.scan(TagAttributes) do |key, value|
          @attributes[key] = value
        end
      else
        raise SyntaxError.new("Syntax Error in 'table_row loop' - Valid syntax: table_row [item] in [collection] cols=3")
      end

      super
    end

    def render(context)
      collection = context[@collection_name] or return ''

      if @attributes['limit'] or @attributes['offset']
        limit = context[@attributes['limit']] || -1
        offset = context[@attributes['offset']] || 0
        collection = collection[offset.to_i..(limit.to_i + offset.to_i - 1)]
      end

      length = collection.length

      cols = context[@attributes['cols']].to_i

      row = 1
      col = 0

      result = "<tr class=\"row1\">\n"
      context.stack do

        collection.each_with_index do |item, index|
          context[@variable_name] = item
          context['tablerowloop'] = {
            'length'  => length,
            'index'   => index + 1,
            'index0'  => index,
            'col'     => col + 1,
            'col0'    => col,
            'index0'  => index,
            'rindex'  => length - index,
            'rindex0' => length - index -1,
            'first'   => (index == 0),
            'last'    => (index == length - 1),
            'col_first' => (col == 0),
            'col_last'  => (col == cols - 1)
          }


          col += 1

          result << "<td class=\"col#{col}\">" << render_all(@nodelist, context) << '</td>'

          if col == cols and not (index == length - 1)
            col  = 0
            row += 1
            result << "</tr>\n<tr class=\"row#{row}\">"
          end

        end
      end
      result << "</tr>\n"
      result
    end
  end

  Template.register_tag('tablerow', TableRow)
end
