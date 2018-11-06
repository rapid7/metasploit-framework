unless Array.method_defined? :combination
  require 'backports/tools/arguments'
  require 'enumerator'

  class Array
    def combination(num)
      num = Backports.coerce_to_int(num)
      return to_enum(:combination, num) unless block_given?
      return self unless (0..size).include? num
      # Implementation note: slightly tricky.
                                               # Example: self = 1..7, num = 3
      picks = (0...num).to_a                   # picks start at 0, 1, 2
      max_index = ((size-num)...size).to_a           # max (index for a given pick) is [4, 5, 6]
      pick_max_pairs = picks.zip(max_index).reverse  # pick_max_pairs = [[2, 6], [1, 5], [0, 4]]
      leave = Proc.new{return self}
      loop do
        yield values_at(*picks)
        move = pick_max_pairs.find(leave){|pick, max| picks[pick] < max}.first
        new_index = picks[move] + 1
        picks[move...num] = (new_index...(new_index+num-move)).to_a
      end
    end
  end
end
