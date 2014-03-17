#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/main'

module Metasm

# a Renderable element has a method #render that returns an array of [String or Renderable]
module Renderable
  def to_s
    render.join
  end

  # yields each Expr seen in #render (recursive)
  def each_expr
    r = proc { |e|
      case e
      when Expression
        yield e
        r[e.lexpr] ; r[e.rexpr]
      when Renderable
        e.render.each { |re| r[re] }
      end
    }
    r[self]
  end
end


class Instruction
  include Renderable
  def render
    @cpu.render_instruction(self)
  end
end

class Label
  include Renderable
  def render
    [@name + ':']
  end
end

class CPU
  # renders an instruction
  # may use instruction-global properties to render an argument (eg specify pointer size if not implicit)
  def render_instruction(i)
    r = []
    r << i.opname
    r << ' '
    i.args.each { |a| r << a << ', ' }
    r.pop
    r
  end

  # ease debugging in irb
  def inspect
    "#<#{self.class}:#{'%x' % object_id} ... >"
  end
end

class Expression
  include Renderable
  attr_accessor :render_info

  # this is an accessor to @@render_int, the lambda used to render integers > 10
  # usage: Expression.render_int = lambda { |e| '0x%x' % e }
  #  or    Expression.render_int { |e| '0x%x' % e }
  # XXX the returned string should be suitable for inclusion in a label name etc
  def self.render_int(&b)
    if b
      @@render_int = b
    else
      @@render_int
    end
  end
  def self.render_int=(p)
 		@@render_int = p
  end
  @@render_int = nil

  def render_integer(e)
        if render_info and @render_info[:char]
          ee = e
          v = []
          while ee > 0
            v << (ee & 0xff)
            ee >>= 8
          end
          v.reverse! if @render_info[:char] == :big
          if not v.empty? and v.all? { |c| c < 0x7f }
            # XXX endianness
        return "'" + v.pack('C*').inspect.gsub("'") { '\\\'' }[1...-1] + "'"
          end
        end
        if e < 0
          neg = true
          e = -e
        end
        if e < 10; e = e.to_s
    elsif @@render_int
      e = @@render_int[e]
        else
          e = '%xh' % e
          e = '0' << e unless (?0..?9).include? e[0]
        end
        e = '-' << e if neg
      e
  end

  NOSQ1 = NOSQ2 = {:* => [:*], :+ => [:+, :-, :*], :- => [:+, :-, :*]}
  NOSQ2[:-] = [:*]
  def render
    l = @lexpr.kind_of?(Integer) ? render_integer(@lexpr) : @lexpr
    r = @rexpr.kind_of?(Integer) ? render_integer(@rexpr) : @rexpr
    l = ['(', l, ')'] if @lexpr.kind_of? Expression and (not oa = NOSQ1[@op] or not oa.include?(@lexpr.op))
    r = ['(', r, ')'] if @rexpr.kind_of? Expression and (not oa = NOSQ2[@op] or not oa.include?(@rexpr.op))
    op = @op if l or @op != :+
    if op == :+
      r0 = [r].flatten.first
      r0 = r0.render.flatten.first while r0.kind_of? Renderable
      op = nil if (r0.kind_of? Integer and r0 < 0) or (r0.kind_of? String and r0[0] == ?-) or r0 == :-
    end
    [l, op, r].compact
  end
end
end
