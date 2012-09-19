module Arithmetic
  include Treetop::Runtime
  
  def root
    @root || :expression
  end
  
  def _nt_expression
    start_index = index
    cached = node_cache[:expression][index]
    if cached
      @index = cached.interval.end
      return cached
    end
    
    i0 = index
    r1 = _nt_comparative
    if r1.success?
      r0 = r1
    else
      r2 = _nt_additive
      if r2.success?
        r0 = r2
      else
        self.index = i0
        r0 = ParseFailure.new(input, i0)
      end
    end
    
    node_cache[:expression][start_index] = r0
    
    return r0
  end
  
  module Comparative0
    def operand_1
      elements[0]
    end
    
    def space
      elements[1]
    end
    
    def operator
      elements[2]
    end
    
    def space
      elements[3]
    end
    
    def operand_2
      elements[4]
    end
  end
  
  def _nt_comparative
    start_index = index
    cached = node_cache[:comparative][index]
    if cached
      @index = cached.interval.end
      return cached
    end
    
    i0, s0 = index, []
    r1 = _nt_additive
    s0 << r1
    if r1.success?
      r2 = _nt_space
      s0 << r2
      if r2.success?
        r3 = _nt_equality_op
        s0 << r3
        if r3.success?
          r4 = _nt_space
          s0 << r4
          if r4.success?
            r5 = _nt_additive
            s0 << r5
          end
        end
      end
    end
    if s0.last.success?
      r0 = (BinaryOperation).new(input, i0...index, s0)
      r0.extend(Comparative0)
    else
      self.index = i0
      r0 = ParseFailure.new(input, i0)
    end
    
    node_cache[:comparative][start_index] = r0
    
    return r0
  end
  
  module EqualityOp0
    def apply(a, b)
      a == b
    end
  end
  
  def _nt_equality_op
    start_index = index
    cached = node_cache[:equality_op][index]
    if cached
      @index = cached.interval.end
      return cached
    end
    
    r0 = parse_terminal('==', SyntaxNode, EqualityOp0)
    
    node_cache[:equality_op][start_index] = r0
    
    return r0
  end
  
  module Additive0
    def operand_1
      elements[0]
    end
    
    def space
      elements[1]
    end
    
    def operator
      elements[2]
    end
    
    def space
      elements[3]
    end
    
    def operand_2
      elements[4]
    end
  end
  
  def _nt_additive
    start_index = index
    cached = node_cache[:additive][index]
    if cached
      @index = cached.interval.end
      return cached
    end
    
    i0 = index
    i1, s1 = index, []
    r2 = _nt_multitive
    s1 << r2
    if r2.success?
      r3 = _nt_space
      s1 << r3
      if r3.success?
        r4 = _nt_additive_op
        s1 << r4
        if r4.success?
          r5 = _nt_space
          s1 << r5
          if r5.success?
            r6 = _nt_additive
            s1 << r6
          end
        end
      end
    end
    if s1.last.success?
      r1 = (BinaryOperation).new(input, i1...index, s1)
      r1.extend(Additive0)
    else
      self.index = i1
      r1 = ParseFailure.new(input, i1)
    end
    if r1.success?
      r0 = r1
    else
      r7 = _nt_multitive
      if r7.success?
        r0 = r7
      else
        self.index = i0
        r0 = ParseFailure.new(input, i0)
      end
    end
    
    node_cache[:additive][start_index] = r0
    
    return r0
  end
  
  module AdditiveOp0
    def apply(a, b)
      a + b
    end
  end
  
  module AdditiveOp1
    def apply(a, b)
      a - b
    end
  end
  
  def _nt_additive_op
    start_index = index
    cached = node_cache[:additive_op][index]
    if cached
      @index = cached.interval.end
      return cached
    end
    
    i0 = index
    r1 = parse_terminal('+', SyntaxNode, AdditiveOp0)
    if r1.success?
      r0 = r1
    else
      r2 = parse_terminal('-', SyntaxNode, AdditiveOp1)
      if r2.success?
        r0 = r2
      else
        self.index = i0
        r0 = ParseFailure.new(input, i0)
      end
    end
    
    node_cache[:additive_op][start_index] = r0
    
    return r0
  end
  
  module Multitive0
    def operand_1
      elements[0]
    end
    
    def space
      elements[1]
    end
    
    def operator
      elements[2]
    end
    
    def space
      elements[3]
    end
    
    def operand_2
      elements[4]
    end
  end
  
  def _nt_multitive
    start_index = index
    cached = node_cache[:multitive][index]
    if cached
      @index = cached.interval.end
      return cached
    end
    
    i0 = index
    i1, s1 = index, []
    r2 = _nt_primary
    s1 << r2
    if r2.success?
      r3 = _nt_space
      s1 << r3
      if r3.success?
        r4 = _nt_multitive_op
        s1 << r4
        if r4.success?
          r5 = _nt_space
          s1 << r5
          if r5.success?
            r6 = _nt_multitive
            s1 << r6
          end
        end
      end
    end
    if s1.last.success?
      r1 = (BinaryOperation).new(input, i1...index, s1)
      r1.extend(Multitive0)
    else
      self.index = i1
      r1 = ParseFailure.new(input, i1)
    end
    if r1.success?
      r0 = r1
    else
      r7 = _nt_primary
      if r7.success?
        r0 = r7
      else
        self.index = i0
        r0 = ParseFailure.new(input, i0)
      end
    end
    
    node_cache[:multitive][start_index] = r0
    
    return r0
  end
  
  module MultitiveOp0
    def apply(a, b)
      a * b
    end
  end
  
  module MultitiveOp1
    def apply(a, b)
      a / b
    end
  end
  
  def _nt_multitive_op
    start_index = index
    cached = node_cache[:multitive_op][index]
    if cached
      @index = cached.interval.end
      return cached
    end
    
    i0 = index
    r1 = parse_terminal('*', SyntaxNode, MultitiveOp0)
    if r1.success?
      r0 = r1
    else
      r2 = parse_terminal('/', SyntaxNode, MultitiveOp1)
      if r2.success?
        r0 = r2
      else
        self.index = i0
        r0 = ParseFailure.new(input, i0)
      end
    end
    
    node_cache[:multitive_op][start_index] = r0
    
    return r0
  end
  
  module Primary0
    def space
      elements[1]
    end
    
    def expression
      elements[2]
    end
    
    def space
      elements[3]
    end
    
  end
  
  module Primary1
    def eval(env={})
      expression.eval(env)
    end
  end
  
  def _nt_primary
    start_index = index
    cached = node_cache[:primary][index]
    if cached
      @index = cached.interval.end
      return cached
    end
    
    i0 = index
    r1 = _nt_variable
    if r1.success?
      r0 = r1
    else
      r2 = _nt_number
      if r2.success?
        r0 = r2
      else
        i3, s3 = index, []
        r4 = parse_terminal('(', SyntaxNode)
        s3 << r4
        if r4.success?
          r5 = _nt_space
          s3 << r5
          if r5.success?
            r6 = _nt_expression
            s3 << r6
            if r6.success?
              r7 = _nt_space
              s3 << r7
              if r7.success?
                r8 = parse_terminal(')', SyntaxNode)
                s3 << r8
              end
            end
          end
        end
        if s3.last.success?
          r3 = (SyntaxNode).new(input, i3...index, s3)
          r3.extend(Primary0)
          r3.extend(Primary1)
        else
          self.index = i3
          r3 = ParseFailure.new(input, i3)
        end
        if r3.success?
          r0 = r3
        else
          self.index = i0
          r0 = ParseFailure.new(input, i0)
        end
      end
    end
    
    node_cache[:primary][start_index] = r0
    
    return r0
  end
  
  module Variable0
    def eval(env={})
      env[name]
    end
    
    def name
      text_value
    end
  end
  
  def _nt_variable
    start_index = index
    cached = node_cache[:variable][index]
    if cached
      @index = cached.interval.end
      return cached
    end
    
    s0, i0 = [], index
    loop do
      r1 = parse_char_class(/[a-z]/, 'a-z', SyntaxNode)
      if r1.success?
        s0 << r1
      else
        break
      end
    end
    if s0.empty?
      self.index = i0
      r0 = ParseFailure.new(input, i0)
    else
      r0 = SyntaxNode.new(input, i0...index, s0)
      r0.extend(Variable0)
    end
    
    node_cache[:variable][start_index] = r0
    
    return r0
  end
  
  module Number0
  end
  
  module Number1
    def eval(env={})
      text_value.to_i
    end
  end
  
  def _nt_number
    start_index = index
    cached = node_cache[:number][index]
    if cached
      @index = cached.interval.end
      return cached
    end
    
    i0 = index
    i1, s1 = index, []
    r2 = parse_char_class(/[1-9]/, '1-9', SyntaxNode)
    s1 << r2
    if r2.success?
      s3, i3 = [], index
      loop do
        r4 = parse_char_class(/[0-9]/, '0-9', SyntaxNode)
        if r4.success?
          s3 << r4
        else
          break
        end
      end
      r3 = SyntaxNode.new(input, i3...index, s3)
      s1 << r3
    end
    if s1.last.success?
      r1 = (SyntaxNode).new(input, i1...index, s1)
      r1.extend(Number0)
    else
      self.index = i1
      r1 = ParseFailure.new(input, i1)
    end
    if r1.success?
      r0 = r1
      r0.extend(Number1)
    else
      r5 = parse_terminal('0', SyntaxNode)
      if r5.success?
        r0 = r5
        r0.extend(Number1)
      else
        self.index = i0
        r0 = ParseFailure.new(input, i0)
      end
    end
    
    node_cache[:number][start_index] = r0
    
    return r0
  end
  
  def _nt_space
    start_index = index
    cached = node_cache[:space][index]
    if cached
      @index = cached.interval.end
      return cached
    end
    
    s0, i0 = [], index
    loop do
      r1 = parse_terminal(' ', SyntaxNode)
      if r1.success?
        s0 << r1
      else
        break
      end
    end
    r0 = SyntaxNode.new(input, i0...index, s0)
    
    node_cache[:space][start_index] = r0
    
    return r0
  end
  
end

class ArithmeticParser < Treetop::Runtime::CompiledParser
  include Arithmetic
end
