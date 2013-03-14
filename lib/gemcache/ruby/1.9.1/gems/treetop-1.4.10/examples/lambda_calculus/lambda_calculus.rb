module LambdaCalculus
  include Treetop::Runtime
  
  def root
    @root || :program
  end
  
  include Arithmetic
  
  module Program0
    def space
      elements[1]
    end
    
    def expression
      elements[2]
    end
  end
  
  module Program1
    def expression
      elements[0]
    end
    
    def more_expressions
      elements[1]
    end
  end
  
  module Program2
    def eval(env={})
      env = env.clone
      last_eval = nil
      expressions.each do |exp|
        last_eval = exp.eval(env)
      end
      last_eval
    end
    
    def expressions
      [expression] + more_expressions.elements.map {|elt| elt.expression}
    end
  end
  
  def _nt_program
    start_index = index
    cached = node_cache[:program][index]
    if cached
      @index = cached.interval.end
      return cached
    end
    
    i0, s0 = index, []
    r1 = _nt_expression
    s0 << r1
    if r1.success?
      s2, i2 = [], index
      loop do
        i3, s3 = index, []
        r4 = parse_terminal(';', SyntaxNode)
        s3 << r4
        if r4.success?
          r5 = _nt_space
          s3 << r5
          if r5.success?
            r6 = _nt_expression
            s3 << r6
          end
        end
        if s3.last.success?
          r3 = (SyntaxNode).new(input, i3...index, s3)
          r3.extend(Program0)
        else
          self.index = i3
          r3 = ParseFailure.new(input, i3)
        end
        if r3.success?
          s2 << r3
        else
          break
        end
      end
      r2 = SyntaxNode.new(input, i2...index, s2)
      s0 << r2
    end
    if s0.last.success?
      r0 = (SyntaxNode).new(input, i0...index, s0)
      r0.extend(Program1)
      r0.extend(Program2)
    else
      self.index = i0
      r0 = ParseFailure.new(input, i0)
    end
    
    node_cache[:program][start_index] = r0
    
    return r0
  end
  
  def _nt_expression
    start_index = index
    cached = node_cache[:expression][index]
    if cached
      @index = cached.interval.end
      return cached
    end
    
    i0 = index
    r1 = _nt_definition
    if r1.success?
      r0 = r1
    else
      r2 = _nt_conditional
      if r2.success?
        r0 = r2
      else
        r3 = _nt_application
        if r3.success?
          r0 = r3
        else
          r4 = _nt_function
          if r4.success?
            r0 = r4
          else
            r5 = super
            if r5.success?
              r0 = r5
            else
              self.index = i0
              r0 = ParseFailure.new(input, i0)
            end
          end
        end
      end
    end
    
    node_cache[:expression][start_index] = r0
    
    return r0
  end
  
  module Definition0
    def space
      elements[1]
    end
    
    def variable
      elements[2]
    end
    
    def space
      elements[3]
    end
    
    def expression
      elements[4]
    end
  end
  
  module Definition1
    def eval(env)
      env[variable.name] = expression.eval(env)
    end
  end
  
  def _nt_definition
    start_index = index
    cached = node_cache[:definition][index]
    if cached
      @index = cached.interval.end
      return cached
    end
    
    i0, s0 = index, []
    r1 = parse_terminal('def', SyntaxNode)
    s0 << r1
    if r1.success?
      r2 = _nt_space
      s0 << r2
      if r2.success?
        r3 = _nt_variable
        s0 << r3
        if r3.success?
          r4 = _nt_space
          s0 << r4
          if r4.success?
            r5 = _nt_expression
            s0 << r5
          end
        end
      end
    end
    if s0.last.success?
      r0 = (SyntaxNode).new(input, i0...index, s0)
      r0.extend(Definition0)
      r0.extend(Definition1)
    else
      self.index = i0
      r0 = ParseFailure.new(input, i0)
    end
    
    node_cache[:definition][start_index] = r0
    
    return r0
  end
  
  module Conditional0
    def space
      elements[1]
    end
    
    def space
      elements[3]
    end
    
    def condition
      elements[4]
    end
    
    def space
      elements[5]
    end
    
    def space
      elements[7]
    end
    
    def true_case
      elements[8]
    end
    
    def space
      elements[9]
    end
    
    def space
      elements[11]
    end
    
    def false_case
      elements[12]
    end
  end
  
  module Conditional1
    def eval(env)
      if condition.eval(env)
        true_case.eval(env)
      else
        false_case.eval(env)
      end
    end
  end
  
  def _nt_conditional
    start_index = index
    cached = node_cache[:conditional][index]
    if cached
      @index = cached.interval.end
      return cached
    end
    
    i0, s0 = index, []
    r1 = parse_terminal('if', SyntaxNode)
    s0 << r1
    if r1.success?
      r2 = _nt_space
      s0 << r2
      if r2.success?
        r3 = parse_terminal('(', SyntaxNode)
        s0 << r3
        if r3.success?
          r4 = _nt_space
          s0 << r4
          if r4.success?
            r5 = _nt_expression
            s0 << r5
            if r5.success?
              r6 = _nt_space
              s0 << r6
              if r6.success?
                r7 = parse_terminal(')', SyntaxNode)
                s0 << r7
                if r7.success?
                  r8 = _nt_space
                  s0 << r8
                  if r8.success?
                    r9 = _nt_expression
                    s0 << r9
                    if r9.success?
                      r10 = _nt_space
                      s0 << r10
                      if r10.success?
                        r11 = parse_terminal('else', SyntaxNode)
                        s0 << r11
                        if r11.success?
                          r12 = _nt_space
                          s0 << r12
                          if r12.success?
                            r13 = _nt_expression
                            s0 << r13
                          end
                        end
                      end
                    end
                  end
                end
              end
            end
          end
        end
      end
    end
    if s0.last.success?
      r0 = (SyntaxNode).new(input, i0...index, s0)
      r0.extend(Conditional0)
      r0.extend(Conditional1)
    else
      self.index = i0
      r0 = ParseFailure.new(input, i0)
    end
    
    node_cache[:conditional][start_index] = r0
    
    return r0
  end
  
  def _nt_primary
    start_index = index
    cached = node_cache[:primary][index]
    if cached
      @index = cached.interval.end
      return cached
    end
    
    i0 = index
    r1 = _nt_application
    if r1.success?
      r0 = r1
    else
      r2 = super
      if r2.success?
        r0 = r2
      else
        self.index = i0
        r0 = ParseFailure.new(input, i0)
      end
    end
    
    node_cache[:primary][start_index] = r0
    
    return r0
  end
  
  module Application0
    def operator
      elements[0]
    end
    
    def space
      elements[1]
    end
    
    def expression
      elements[2]
    end
  end
  
  module Application1
    def eval(env={})
      left_associative_apply(operator.eval(env), env)
    end
    
    def left_associative_apply(operator, env)
      if expression.instance_of?(Application)
        expression.left_associative_apply(operator.apply(expression.operator.eval(env)), env)
      else
        operator.apply(expression.eval(env))
      end
    end
    
    def to_s(env={})
      operator.to_s(env) + ' ' + expression.to_s(env)
    end
  end
  
  def _nt_application
    start_index = index
    cached = node_cache[:application][index]
    if cached
      @index = cached.interval.end
      return cached
    end
    
    i0, s0 = index, []
    r1 = _nt_operator
    s0 << r1
    if r1.success?
      r2 = _nt_space
      s0 << r2
      if r2.success?
        r3 = _nt_expression
        s0 << r3
      end
    end
    if s0.last.success?
      r0 = (Application).new(input, i0...index, s0)
      r0.extend(Application0)
      r0.extend(Application1)
    else
      self.index = i0
      r0 = ParseFailure.new(input, i0)
    end
    
    node_cache[:application][start_index] = r0
    
    return r0
  end
  
  def _nt_operator
    start_index = index
    cached = node_cache[:operator][index]
    if cached
      @index = cached.interval.end
      return cached
    end
    
    i0 = index
    r1 = _nt_function
    if r1.success?
      r0 = r1
    else
      r2 = _nt_variable
      if r2.success?
        r0 = r2
      else
        self.index = i0
        r0 = ParseFailure.new(input, i0)
      end
    end
    
    node_cache[:operator][start_index] = r0
    
    return r0
  end
  
  def _nt_non_application
    start_index = index
    cached = node_cache[:non_application][index]
    if cached
      @index = cached.interval.end
      return cached
    end
    
    i0 = index
    r1 = _nt_function
    if r1.success?
      r0 = r1
    else
      r2 = _nt_variable
      if r2.success?
        r0 = r2
      else
        self.index = i0
        r0 = ParseFailure.new(input, i0)
      end
    end
    
    node_cache[:non_application][start_index] = r0
    
    return r0
  end
  
  module Function0
    def param
      elements[1]
    end
    
    def body
      elements[3]
    end
    
  end
  
  module Function1
    class Closure
      attr_reader :env, :function
      
      def initialize(function, env)
        @function = function
        @env = env
      end
    
      def apply(arg)
        function.body.eval(function.param.bind(arg, env))
      end
    
      def to_s(other_env={})
        "\\#{function.param.to_s}(#{function.body.to_s(other_env.merge(env))})"
      end
    end
    
    def eval(env={})
      Closure.new(self, env)
    end
    
    def to_s(env={})
      eval(env).to_s
    end
  end
  
  def _nt_function
    start_index = index
    cached = node_cache[:function][index]
    if cached
      @index = cached.interval.end
      return cached
    end
    
    i0, s0 = index, []
    r1 = parse_terminal('\\', SyntaxNode)
    s0 << r1
    if r1.success?
      r2 = _nt_variable
      s0 << r2
      if r2.success?
        r3 = parse_terminal('(', SyntaxNode)
        s0 << r3
        if r3.success?
          r4 = _nt_expression
          s0 << r4
          if r4.success?
            r5 = parse_terminal(')', SyntaxNode)
            s0 << r5
          end
        end
      end
    end
    if s0.last.success?
      r0 = (SyntaxNode).new(input, i0...index, s0)
      r0.extend(Function0)
      r0.extend(Function1)
    else
      self.index = i0
      r0 = ParseFailure.new(input, i0)
    end
    
    node_cache[:function][start_index] = r0
    
    return r0
  end
  
  module Variable0
    def bind(value, env)
      env.merge(name => value)
    end

    def to_s(env={})
      env.has_key?(name) ? env[name].to_s : name
  end
  end
  
  module Variable1
  end
  
  def _nt_variable
    start_index = index
    cached = node_cache[:variable][index]
    if cached
      @index = cached.interval.end
      return cached
    end
    
    i0, s0 = index, []
    i1 = index
    r2 = _nt_keyword
    if r2.success?
      r1 = ParseFailure.new(input, i1)
    else
      self.index = i1
      r1 = SyntaxNode.new(input, index...index)
    end
    s0 << r1
    if r1.success?
      r3 = super
      r3.extend(Variable0)
      s0 << r3
    end
    if s0.last.success?
      r0 = (SyntaxNode).new(input, i0...index, s0)
      r0.extend(Variable1)
    else
      self.index = i0
      r0 = ParseFailure.new(input, i0)
    end
    
    node_cache[:variable][start_index] = r0
    
    return r0
  end
  
  module Keyword0
  end
  
  def _nt_keyword
    start_index = index
    cached = node_cache[:keyword][index]
    if cached
      @index = cached.interval.end
      return cached
    end
    
    i0, s0 = index, []
    i1 = index
    r2 = parse_terminal('if', SyntaxNode)
    if r2.success?
      r1 = r2
    else
      r3 = parse_terminal('else', SyntaxNode)
      if r3.success?
        r1 = r3
      else
        self.index = i1
        r1 = ParseFailure.new(input, i1)
      end
    end
    s0 << r1
    if r1.success?
      i4 = index
      r5 = _nt_non_space_char
      if r5.success?
        r4 = ParseFailure.new(input, i4)
      else
        self.index = i4
        r4 = SyntaxNode.new(input, index...index)
      end
      s0 << r4
    end
    if s0.last.success?
      r0 = (SyntaxNode).new(input, i0...index, s0)
      r0.extend(Keyword0)
    else
      self.index = i0
      r0 = ParseFailure.new(input, i0)
    end
    
    node_cache[:keyword][start_index] = r0
    
    return r0
  end
  
  module NonSpaceChar0
  end
  
  def _nt_non_space_char
    start_index = index
    cached = node_cache[:non_space_char][index]
    if cached
      @index = cached.interval.end
      return cached
    end
    
    i0, s0 = index, []
    i1 = index
    r2 = parse_char_class(/[ \n]/, ' \n', SyntaxNode)
    if r2.success?
      r1 = ParseFailure.new(input, i1)
    else
      self.index = i1
      r1 = SyntaxNode.new(input, index...index)
    end
    s0 << r1
    if r1.success?
      r3 = parse_anything(SyntaxNode)
      s0 << r3
    end
    if s0.last.success?
      r0 = (SyntaxNode).new(input, i0...index, s0)
      r0.extend(NonSpaceChar0)
    else
      self.index = i0
      r0 = ParseFailure.new(input, i0)
    end
    
    node_cache[:non_space_char][start_index] = r0
    
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
      r1 = parse_char_class(/[ \n]/, ' \n', SyntaxNode)
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

class LambdaCalculusParser < Treetop::Runtime::CompiledParser
  include LambdaCalculus
end
