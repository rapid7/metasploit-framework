###
### $Release: 2.7.0 $
### copyright(c) 2006-2011 kuwata-lab.com all rights reserved.
###

require 'cgi'


module Erubis


  ##
  ## for preprocessing
  ##
  class PreprocessingEruby < Erubis::Eruby

    def initialize(input, params={})
      params = params.dup
      params[:pattern] ||= '\[% %\]'    # use '[%= %]' instead of '<%= %>'
      #params[:escape] = true            # transport '[%= %]' and '[%== %]'
      super
    end

    def add_expr_escaped(src, code)
      add_expr_literal(src, "_decode((#{code}))")
    end

  end


  ##
  ## helper methods for preprocessing
  ##
  module PreprocessingHelper

    module_function

    def _p(arg)
      return "<%=#{arg}%>"
    end

    def _P(arg)
      return "<%=h(#{arg})%>"
    end

    alias _? _p

    def _decode(arg)
      arg = arg.to_s
      arg.gsub!(/%3C%25(?:=|%3D)(.*?)%25%3E/) { "<%=#{CGI.unescape($1)}%>" }
      arg.gsub!(/&lt;%=(.*?)%&gt;/) { "<%=#{CGI.unescapeHTML($1)}%>" }
      return arg
    end

  end


end
