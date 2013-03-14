module CodeRay
module Encoders
  
  # Makes a statistic for the given tokens.
  # 
  # Alias: +stats+
  class Statistic < Encoder
    
    register_for :statistic
    
    attr_reader :type_stats, :real_token_count  # :nodoc:
    
    TypeStats = Struct.new :count, :size  # :nodoc:
    
  protected
    
    def setup options
      super
      
      @type_stats = Hash.new { |h, k| h[k] = TypeStats.new 0, 0 }
      @real_token_count = 0
    end
    
    STATS = <<-STATS  # :nodoc:

Code Statistics

Tokens            %8d
  Non-Whitespace  %8d
Bytes Total       %8d

Token Types (%d):
  type                     count     ratio    size (average)
-------------------------------------------------------------
%s
    STATS
    
    TOKEN_TYPES_ROW = <<-TKR  # :nodoc:
  %-20s  %8d  %6.2f %%   %5.1f
    TKR
    
    def finish options
      all = @type_stats['TOTAL']
      all_count, all_size = all.count, all.size
      @type_stats.each do |type, stat|
        stat.size /= stat.count.to_f
      end
      types_stats = @type_stats.sort_by { |k, v| [-v.count, k.to_s] }.map do |k, v|
        TOKEN_TYPES_ROW % [k, v.count, 100.0 * v.count / all_count, v.size]
      end.join
      @out << STATS % [
        all_count, @real_token_count, all_size,
        @type_stats.delete_if { |k, v| k.is_a? String }.size,
        types_stats
      ]
      
      super
    end
    
  public
    
    def text_token text, kind
      @real_token_count += 1 unless kind == :space
      @type_stats[kind].count += 1
      @type_stats[kind].size += text.size
      @type_stats['TOTAL'].size += text.size
      @type_stats['TOTAL'].count += 1
    end
    
    # TODO Hierarchy handling
    def begin_group kind
      block_token ':begin_group', kind
    end
    
    def end_group kind
      block_token ':end_group', kind
    end
    
    def begin_line kind
      block_token ':begin_line', kind
    end
    
    def end_line kind
      block_token ':end_line', kind
    end
    
    def block_token action, kind
      @type_stats['TOTAL'].count += 1
      @type_stats[action].count += 1
      @type_stats[kind].count += 1
    end
    
  end
  
end
end
