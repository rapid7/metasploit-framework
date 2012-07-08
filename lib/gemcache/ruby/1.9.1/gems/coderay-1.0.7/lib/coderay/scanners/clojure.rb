# encoding: utf-8
module CodeRay
  module Scanners
    
    # Clojure scanner by Licenser.
    class Clojure < Scanner
      
      register_for :clojure
      file_extension 'clj'
      
      SPECIAL_FORMS = %w[
        def if do let quote var fn loop recur throw try catch monitor-enter monitor-exit .
        new 
      ]  # :nodoc:
      
      CORE_FORMS = %w[
        + - -> ->> .. / * <= < = == >= > accessor aclone add-classpath add-watch
        agent agent-error agent-errors aget alength alias all-ns alter alter-meta!
        alter-var-root amap ancestors and apply areduce array-map aset aset-boolean
        aset-byte aset-char aset-double aset-float aset-int aset-long aset-short
        assert assoc assoc! assoc-in associative? atom await await-for bases bean
        bigdec bigint binding bit-and bit-and-not bit-clear bit-flip bit-not bit-or
        bit-set bit-shift-left bit-shift-right bit-test bit-xor boolean boolean-array
        booleans bound-fn bound-fn* bound? butlast byte byte-array bytes case cast char
        char-array char-escape-string char-name-string char? chars class class?
        clear-agent-errors clojure-version coll? comment commute comp comparator
        compare compare-and-set! compile complement concat cond condp conj conj!
        cons constantly construct-proxy contains? count counted? create-ns
        create-struct cycle dec decimal? declare definline defmacro defmethod defmulti
        defn defn- defonce defprotocol defrecord defstruct deftype delay delay?
        deliver denominator deref derive descendants disj disj! dissoc dissoc!
        distinct distinct? doall doc dorun doseq dosync dotimes doto double
        double-array doubles drop drop-last drop-while empty empty? ensure
        enumeration-seq error-handler error-mode eval even? every? extend
        extend-protocol extend-type extenders extends? false? ffirst file-seq
        filter find find-doc find-ns find-var first float float-array float?
        floats flush fn fn? fnext for force format future future-call future-cancel
        future-cancelled? future-done? future? gen-class gen-interface gensym get
        get-in get-method get-proxy-class get-thread-bindings get-validator hash
        hash-map hash-set identical? identity if-let if-not ifn? import in-ns
        inc init-proxy instance? int int-array integer? interleave intern
        interpose into into-array ints io! isa? iterate iterator-seq juxt key
        keys keyword keyword? last lazy-cat lazy-seq let letfn line-seq list list*
        list? load load-file load-reader load-string loaded-libs locking long
        long-array longs loop macroexpand macroexpand-1 make-array make-hierarchy
        map map? mapcat max max-key memfn memoize merge merge-with meta methods
        min min-key mod name namespace neg? newline next nfirst nil? nnext not
        not-any? not-empty not-every? not= ns ns-aliases ns-imports ns-interns
        ns-map ns-name ns-publics ns-refers ns-resolve ns-unalias ns-unmap nth
        nthnext num number? numerator object-array odd? or parents partial
        partition pcalls peek persistent! pmap pop pop! pop-thread-bindings
        pos? pr pr-str prefer-method prefers print print-namespace-doc
        print-str printf println println-str prn prn-str promise proxy
        proxy-mappings proxy-super push-thread-bindings pvalues quot rand
        rand-int range ratio? rationalize re-find re-groups re-matcher
        re-matches re-pattern re-seq read read-line read-string reduce ref
        ref-history-count ref-max-history ref-min-history ref-set refer
        refer-clojure reify release-pending-sends rem remove remove-all-methods
        remove-method remove-ns remove-watch repeat repeatedly replace replicate
        require reset! reset-meta! resolve rest restart-agent resultset-seq
        reverse reversible? rseq rsubseq satisfies? second select-keys send
        send-off seq seq? seque sequence sequential? set set-error-handler!
        set-error-mode! set-validator! set? short short-array shorts
        shutdown-agents slurp some sort sort-by sorted-map sorted-map-by
        sorted-set sorted-set-by sorted? special-form-anchor special-symbol?
        split-at split-with str string? struct struct-map subs subseq subvec
        supers swap! symbol symbol? sync syntax-symbol-anchor take take-last
        take-nth take-while test the-ns thread-bound? time to-array to-array-2d
        trampoline transient tree-seq true? type unchecked-add unchecked-dec
        unchecked-divide unchecked-inc unchecked-multiply unchecked-negate
        unchecked-remainder unchecked-subtract underive update-in update-proxy
        use val vals var-get var-set var? vary-meta vec vector vector-of vector?
        when when-first when-let when-not while with-bindings with-bindings*
        with-in-str with-local-vars with-meta with-open with-out-str
        with-precision xml-seq zero? zipmap 
      ]  # :nodoc:
      
      PREDEFINED_CONSTANTS = %w[
        true false nil *1 *2 *3 *agent* *clojure-version* *command-line-args*
        *compile-files* *compile-path* *e *err* *file* *flush-on-newline*
        *in* *ns* *out* *print-dup* *print-length* *print-level* *print-meta*
        *print-readably* *read-eval* *warn-on-reflection*
      ]  # :nodoc:
      
      IDENT_KIND = WordList.new(:ident).
        add(SPECIAL_FORMS, :keyword).
        add(CORE_FORMS, :keyword).
        add(PREDEFINED_CONSTANTS, :predefined_constant)
      
      KEYWORD_NEXT_TOKEN_KIND = WordList.new(nil).
        add(%w[ def defn defn- definline defmacro defmulti defmethod defstruct defonce declare ], :function).
        add(%w[ ns ], :namespace).
        add(%w[ defprotocol defrecord ], :class)
      
      BASIC_IDENTIFIER = /[a-zA-Z$%*\/_+!?&<>\-=]=?[a-zA-Z0-9$&*+!\/_?<>\-\#]*/
      IDENTIFIER = /(?!-\d)(?:(?:#{BASIC_IDENTIFIER}\.)*#{BASIC_IDENTIFIER}(?:\/#{BASIC_IDENTIFIER})?\.?)|\.\.?/
      SYMBOL = /::?#{IDENTIFIER}/o
      DIGIT = /\d/
      DIGIT10 = DIGIT
      DIGIT16 = /[0-9a-f]/i
      DIGIT8 = /[0-7]/
      DIGIT2 = /[01]/
      RADIX16 = /\#x/i
      RADIX8 = /\#o/i
      RADIX2 = /\#b/i
      RADIX10 = /\#d/i
      EXACTNESS = /#i|#e/i
      SIGN = /[\+-]?/
      EXP_MARK = /[esfdl]/i
      EXP = /#{EXP_MARK}#{SIGN}#{DIGIT}+/
      SUFFIX = /#{EXP}?/
      PREFIX10 = /#{RADIX10}?#{EXACTNESS}?|#{EXACTNESS}?#{RADIX10}?/
      PREFIX16 = /#{RADIX16}#{EXACTNESS}?|#{EXACTNESS}?#{RADIX16}/
      PREFIX8 = /#{RADIX8}#{EXACTNESS}?|#{EXACTNESS}?#{RADIX8}/
      PREFIX2 = /#{RADIX2}#{EXACTNESS}?|#{EXACTNESS}?#{RADIX2}/
      UINT10 = /#{DIGIT10}+#*/
      UINT16 = /#{DIGIT16}+#*/
      UINT8 = /#{DIGIT8}+#*/
      UINT2 = /#{DIGIT2}+#*/
      DECIMAL = /#{DIGIT10}+#+\.#*#{SUFFIX}|#{DIGIT10}+\.#{DIGIT10}*#*#{SUFFIX}|\.#{DIGIT10}+#*#{SUFFIX}|#{UINT10}#{EXP}/
      UREAL10 = /#{UINT10}\/#{UINT10}|#{DECIMAL}|#{UINT10}/
      UREAL16 = /#{UINT16}\/#{UINT16}|#{UINT16}/
      UREAL8 = /#{UINT8}\/#{UINT8}|#{UINT8}/
      UREAL2 = /#{UINT2}\/#{UINT2}|#{UINT2}/
      REAL10 = /#{SIGN}#{UREAL10}/
      REAL16 = /#{SIGN}#{UREAL16}/
      REAL8 = /#{SIGN}#{UREAL8}/
      REAL2 = /#{SIGN}#{UREAL2}/
      IMAG10 = /i|#{UREAL10}i/
      IMAG16 = /i|#{UREAL16}i/
      IMAG8 = /i|#{UREAL8}i/
      IMAG2 = /i|#{UREAL2}i/
      COMPLEX10 = /#{REAL10}@#{REAL10}|#{REAL10}\+#{IMAG10}|#{REAL10}-#{IMAG10}|\+#{IMAG10}|-#{IMAG10}|#{REAL10}/
      COMPLEX16 = /#{REAL16}@#{REAL16}|#{REAL16}\+#{IMAG16}|#{REAL16}-#{IMAG16}|\+#{IMAG16}|-#{IMAG16}|#{REAL16}/
      COMPLEX8 = /#{REAL8}@#{REAL8}|#{REAL8}\+#{IMAG8}|#{REAL8}-#{IMAG8}|\+#{IMAG8}|-#{IMAG8}|#{REAL8}/
      COMPLEX2 = /#{REAL2}@#{REAL2}|#{REAL2}\+#{IMAG2}|#{REAL2}-#{IMAG2}|\+#{IMAG2}|-#{IMAG2}|#{REAL2}/
      NUM10 = /#{PREFIX10}?#{COMPLEX10}/
      NUM16 = /#{PREFIX16}#{COMPLEX16}/
      NUM8 = /#{PREFIX8}#{COMPLEX8}/
      NUM2 = /#{PREFIX2}#{COMPLEX2}/
      NUM = /#{NUM10}|#{NUM16}|#{NUM8}|#{NUM2}/
      
    protected
      
      def scan_tokens encoder, options
        
        state = :initial
        kind = nil
        
        until eos?
          
          case state
          when :initial
            if match = scan(/ \s+ | \\\n | , /x)
              encoder.text_token match, :space
            elsif match = scan(/['`\(\[\)\]\{\}]|\#[({]|~@?|[@\^]/)
              encoder.text_token match, :operator
            elsif match = scan(/;.*/)
              encoder.text_token match, :comment  # TODO: recognize (comment ...) too
            elsif match = scan(/\#?\\(?:newline|space|.?)/)
              encoder.text_token match, :char
            elsif match = scan(/\#[ft]/)
              encoder.text_token match, :predefined_constant
            elsif match = scan(/#{IDENTIFIER}/o)
              kind = IDENT_KIND[match]
              encoder.text_token match, kind
              if rest? && kind == :keyword
                if kind = KEYWORD_NEXT_TOKEN_KIND[match]
                  encoder.text_token match, :space if match = scan(/\s+/o)
                  encoder.text_token match, kind if match = scan(/#{IDENTIFIER}/o)
                end
              end
            elsif match = scan(/#{SYMBOL}/o)
              encoder.text_token match, :symbol
            elsif match = scan(/\./)
              encoder.text_token match, :operator
            elsif match = scan(/ \# \^ #{IDENTIFIER} /ox)
              encoder.text_token match, :type
            elsif match = scan(/ (\#)? " /x)
              state = self[1] ? :regexp : :string
              encoder.begin_group state
              encoder.text_token match, :delimiter
            elsif match = scan(/#{NUM}/o) and not matched.empty?
              encoder.text_token match, match[/[.e\/]/i] ? :float : :integer
            else
              encoder.text_token getch, :error
            end
            
          when :string, :regexp
            if match = scan(/[^"\\]+|\\.?/)
              encoder.text_token match, :content
            elsif match = scan(/"/)
              encoder.text_token match, :delimiter
              encoder.end_group state
              state = :initial
            else
              raise_inspect "else case \" reached; %p not handled." % peek(1),
                encoder, state
            end
            
          else
            raise 'else case reached'
            
          end
          
        end
        
        if [:string, :regexp].include? state
          encoder.end_group state
        end
        
        encoder
        
      end
    end
  end
end