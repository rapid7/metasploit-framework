require 'bindata'

# An example of a recursively defined data format.
#
# This example format describes atoms and lists.
# It is recursive because lists can contain other lists.
#
# Atoms - contain a single integer
# Lists - contain a mixture of atoms and lists
#
# The binary representation is:
#
# Atoms - A single byte 'a' followed by an int32 containing the value.
# Lists - A single byte 'l' followed by an int32 denoting the number of
#         items in the list.  This is followed by all the items in the list.
#
# All integers are big endian.
#
#
# A first attempt at a declaration would be:
#
#     class Atom < BinData::Record
#       string  :tag, length: 1, assert: 'a'
#       int32be :val
#     end
#
#     class List < BinData::Record
#       string  :tag,  length: 1, assert: 'l'
#       int32be :num,  value: -> { vals.length }
#       array   :vals, initial_length: :num do
#         choice selection: ??? do
#           atom
#           list
#         end
#       end
#     end
#
# Notice how we get stuck on attemping to write a declaration for
# the contents of the list.  We can't determine if the list item is
# an atom or list because we haven't read it yet.  It appears that
# we can't proceed.
#
# The cause of the problem is that the tag identifying the type is
# coupled with that type.
#
# The solution is to decouple the tag from the type.  We introduce a
# new type 'Term' that is a thin container around the tag plus the
# type (atom or list).
#
# The declaration then becomes:
#
#     class Term < BinData::Record; end  # forward declaration
#
#     class Atom < BinData::Int32be
#     end
#
#     class List < BinData::Record
#       int32be :num,  value: -> { vals.length }
#       array   :vals, type: :term, initial_length: :num
#     end
#
#     class Term < BinData::Record
#       string :tag, length: 1
#       choice :term, selection: :tag do
#         atom 'a'
#         list 'l'
#       end
#     end


class Term < BinData::Record; end  # Forward declaration

class Atom < BinData::Int32be
  def decode
    snapshot
  end

  def self.encode(val)
    Atom.new(val)
  end
end

class List < BinData::Record
  int32be :num,  value: -> { vals.length }
  array   :vals, initial_length: :num, type: :term

  def decode
    vals.collect(&:decode)
  end

  def self.encode(val)
    List.new(vals: val.collect { |v| Term.encode(v) })
  end
end

class Term < BinData::Record
  string :tag, length: 1
  choice :term, selection: :tag do
    atom 'a'
    list 'l'
  end

  def decode
    term.decode
  end

  def self.encode(val)
    if Fixnum === val
      Term.new(tag: 'a', term: Atom.encode(val))
    else
      Term.new(tag: 'l', term: List.encode(val))
    end
  end
end


puts "A single Atom"
p Term.encode(4)
p Term.encode(4).decode
puts

puts "A nested List"
p Term.encode([1, [2, 3], 4])
p Term.encode([1, [2, 3], 4]).decode
