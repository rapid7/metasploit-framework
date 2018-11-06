require 'bit-struct'

class MD < BitStruct
  vector :row, :length => 3 do
    vector :col, :length => 10 do
      float :x, 32
    end
  end
end

md = MD.new
  rows = md.row
    row = rows[2]
      cols = row.col
        col = cols[7]
          col.x = 1.23
        cols[7] = col
      row.col = cols
    rows[2] = row
  md.row = rows

p md
p md.row[2].col[7].x
