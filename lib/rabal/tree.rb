#
# Rabal Tree,rb
# A basic Tree structure
#

class Tree

  include Enumerable

  # The name of this Tree
  attr_accessor :name

  # The parent of this node.  If this is nil then this Tree is a
  # root.
  attr_accessor :parent

  # The children of this node.  If this Hash is empty, then this
  # Tree is a leaf.
  attr_accessor :children

  # An abstract data point that can be utilized by child classes
  # for whatever they like.  If this is non-nil and responds to
  # method calls it will be searched as part of the
  # 'method_missing' protocol.
  attr_accessor :parameters

  #
  # Create a new Tree with the given object.to_s as its +name+.
  #

  def initialize(name)
    @name   	= name.to_s
    @parent 	= nil
    @children   = {}
    @parameters = nil
  end

  #
  # Return true if this Tree has no children.
  #
  def is_leaf?
    @children.empty?
  end

  # 
  # Return true if this Tree has no parent.
  #
  def is_root?
    @parent.nil?
  end

  # 
  # Return the root node of the tree
  #
  def root
    return self if is_root?
    return @parent.root
  end

  #
  # Return the distance from the root
  #
  def depth
    return 0 if is_root?
    return (1 + @parent.depth)
  end

  #
  # Attach the given tree at the indicated path.  The path given
  # is always assumed to be from the root of the Tree being
  # attached to.
  #
  # The path is given as a string separated by '/'.  Each portion
  # of the string is matched against the name of the particular
  # tree.  
  #
  # Given :
  #
  #   a --- b --- c
  #	\ 
  # 	d - e --- f
  #  		\
  #   		g - h
  #
  # * the path +a/b/c+ will match the path to Tree +c+
  # * the path +d/e/g+ will _not_ match anything as the path must start at +a+ here
  # * the path +a/d/e+ will _not_ match anytthin as +e+ is not a child of +d+
  # * the path +a/d/e/g+ will match node +g+
  #
  # Leading and trailing '/' on the path are not necessary and removed.
  #
  def add_at_path(path,subtree)
    parent_tree = tree_at_path(path)
    parent_tree << subtree
    return self
  end

  #
  # Return the Tree that resides at the given path
  #
  def tree_at_path(path_str)
    path_str = path_str.chomp("/").reverse.chomp("/").reverse
    path 	= path_str.split("/")

    # strip of the redundant first match if it is the same as
    # the current node
    find_subtree(path)
  end

  #
  # Add the given object to the Tree as a child of this node.  If
  # the given object is not a Tree then wrap it with a Tree.
  #
  def <<(subtree)
    # this should not generally be the case, but wrap things
    # up to be nice.
    if not subtree.kind_of?(Tree) then
      subtree = Tree.new(subtree)
    end

    subtree.parent = self

    # FIXME: techinically this should no longer be called 'post_add' 
    # but maybe 'add_hook'  
    subtree.post_add

    # Don't overwrite any existing children with the same name,
    # just put the new subtree's children into the children of
    # the already existing subtree.

    if children.has_key?(subtree.name) then
      subtree.children.each_pair do |subtree_child_name,subtree_child_tree|
        children[subtree.name] << subtree_child_tree
      end
    else
      children[subtree.name] = subtree
    end

    return self
  end

  alias :add :<<

  #
  # Allow for Enumerable to be included.  This just wraps walk.
  #
  def each
    self.walk(self,lambda { |tree| yield tree }) 
  end

  #
  # Count how many items are in the tree
  #
  def size
    inject(0) { |count,n| count + 1 }
  end

  # 
  # Walk the tree in a depth first manner, visiting the Tree
  # first, then its children
  #
  def walk(tree,method)
    method.call(tree)
    tree.children.each_pair do |name,child|
      walk(child,method) 
    end
    #for depth first
    #method.call(tree)
  end

  # 
  # Allow for a method call to cascade up the tree looking for a
  # Tree that responds to the call.
  #
  def method_missing(method_id,*params,&block)
    if not parameters.nil? and parameters.respond_to?(method_id) then
      return parameters.send(method_id, *params, &block)
    elsif not is_root? then
      @parent.send method_id, *params, &block
    else
      raise NoMethodError, "undefined method `#{method_id}' for #{name}:Tree"
    end
  end

  #
  # allow for a hook so newly added Tree objects may do custom
  # processing after being added to the tree, but before the tree
  # is walked or processed
  #
  def post_add
  end
  #
  # find the current path of the tree from root to here, return it
  # as a '/' separates string.
  #
  def current_path
    #
    # WMAP: removed the asterixs and modified the first return
    # to just return a '/'
    # 
    return "/" if is_root? 
    return ([name,parent.current_path]).flatten.reverse.join("/")
  end

  #
  # Given the initial path to match as an Array find the Tree that
  # matches that path.
  # 
  def find_subtree(path)
    if path.empty? then
      return self
    else
      possible_child = path.shift
      if children.has_key?(possible_child) then
        children[possible_child].find_subtree(path)
      else
        raise PathNotFoundError, "`#{possible_child}' does not match anything at the current path in the Tree (#{current_path})"
      end
    end
  end

  #
  # Return true of false if the given subtree exists or not
  #
  def has_subtree?(path)
    begin
      find_subtree(path)
      return true
    rescue PathNotFoundError
      return false
    end
  end

  #
  # Allow for numerable to be included. This just wraps walk
  #
  def each
    self.walk(self,lambda { |tree| yield tree })	
  end

  def each_datum
    self.walk(self,lambda { |tree| yield tree.data})
  end
end
