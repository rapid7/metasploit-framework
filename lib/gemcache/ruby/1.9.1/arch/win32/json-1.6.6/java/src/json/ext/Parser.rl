/*
 * This code is copyrighted work by Daniel Luz <dev at mernen dot com>.
 *
 * Distributed under the Ruby and GPLv2 licenses; see COPYING and GPL files
 * for details.
 */
package json.ext;

import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyClass;
import org.jruby.RubyEncoding;
import org.jruby.RubyFloat;
import org.jruby.RubyHash;
import org.jruby.RubyInteger;
import org.jruby.RubyModule;
import org.jruby.RubyNumeric;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.anno.JRubyMethod;
import org.jruby.exceptions.JumpException;
import org.jruby.exceptions.RaiseException;
import org.jruby.runtime.Block;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.Visibility;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;
import org.jruby.util.ConvertBytes;
import static org.jruby.util.ConvertDouble.DoubleConverter;

/**
 * The <code>JSON::Ext::Parser</code> class.
 *
 * <p>This is the JSON parser implemented as a Java class. To use it as the
 * standard parser, set
 *   <pre>JSON.parser = JSON::Ext::Parser</pre>
 * This is performed for you when you <code>include "json/ext"</code>.
 *
 * <p>This class does not perform the actual parsing, just acts as an interface
 * to Ruby code. When the {@link #parse()} method is invoked, a
 * Parser.ParserSession object is instantiated, which handles the process.
 *
 * @author mernen
 */
public class Parser extends RubyObject {
    private final RuntimeInfo info;
    private RubyString vSource;
    private RubyString createId;
    private boolean createAdditions;
    private int maxNesting;
    private boolean allowNaN;
    private boolean symbolizeNames;
    private boolean quirksMode;
    private RubyClass objectClass;
    private RubyClass arrayClass;
    private RubyHash match_string;

    private static final int DEFAULT_MAX_NESTING = 19;

    private static final ByteList JSON_MINUS_INFINITY = new ByteList(ByteList.plain("-Infinity"));
    // constant names in the JSON module containing those values
    private static final String CONST_NAN = "NaN";
    private static final String CONST_INFINITY = "Infinity";
    private static final String CONST_MINUS_INFINITY = "MinusInfinity";

    static final ObjectAllocator ALLOCATOR = new ObjectAllocator() {
        public IRubyObject allocate(Ruby runtime, RubyClass klazz) {
            return new Parser(runtime, klazz);
        }
    };

    /**
     * Multiple-value return for internal parser methods.
     *
     * <p>All the <code>parse<var>Stuff</var></code> methods return instances of
     * <code>ParserResult</code> when successful, or <code>null</code> when
     * there's a problem with the input data.
     */
    static final class ParserResult {
        /**
         * The result of the successful parsing. Should never be
         * <code>null</code>.
         */
        IRubyObject result;
        /**
         * The point where the parser returned.
         */
        int p;

        void update(IRubyObject result, int p) {
            this.result = result;
            this.p = p;
        }
    }

    public Parser(Ruby runtime, RubyClass metaClass) {
        super(runtime, metaClass);
        info = RuntimeInfo.forRuntime(runtime);
    }

    /**
     * <code>Parser.new(source, opts = {})</code>
     *
     * <p>Creates a new <code>JSON::Ext::Parser</code> instance for the string
     * <code>source</code>.
     * It will be configured by the <code>opts</code> Hash.
     * <code>opts</code> can have the following keys:
     *
     * <dl>
     * <dt><code>:max_nesting</code>
     * <dd>The maximum depth of nesting allowed in the parsed data
     * structures. Disable depth checking with <code>:max_nesting => false|nil|0</code>,
     * it defaults to 19.
     *
     * <dt><code>:allow_nan</code>
     * <dd>If set to <code>true</code>, allow <code>NaN</code>,
     * <code>Infinity</code> and <code>-Infinity</code> in defiance of RFC 4627
     * to be parsed by the Parser. This option defaults to <code>false</code>.
     *
     * <dt><code>:symbolize_names</code>
     * <dd>If set to <code>true</code>, returns symbols for the names (keys) in
     * a JSON object. Otherwise strings are returned, which is also the default.
     *
     * <dt><code>:quirks_mode?</code>
     * <dd>If set to <code>true</code>, if the parse is in quirks_mode, false
     * otherwise.
     * 
     * <dt><code>:create_additions</code>
     * <dd>If set to <code>false</code>, the Parser doesn't create additions
     * even if a matchin class and <code>create_id</code> was found. This option
     * defaults to <code>true</code>.
     *
     * <dt><code>:object_class</code>
     * <dd>Defaults to Hash.
     *
     * <dt><code>:array_class</code>
     * <dd>Defaults to Array.
     *
     * <dt><code>:quirks_mode</code>
     * <dd>Enables quirks_mode for parser, that is for example parsing single
     * JSON values instead of documents is possible.
     * </dl>
     */
    @JRubyMethod(name = "new", required = 1, optional = 1, meta = true)
    public static IRubyObject newInstance(IRubyObject clazz, IRubyObject[] args, Block block) {
        Parser parser = (Parser)((RubyClass)clazz).allocate();

        parser.callInit(args, block);

        return parser;
    }

    @JRubyMethod(required = 1, optional = 1, visibility = Visibility.PRIVATE)
    public IRubyObject initialize(ThreadContext context, IRubyObject[] args) {
        Ruby runtime = context.getRuntime();
        if (this.vSource != null) {
            throw runtime.newTypeError("already initialized instance");
         }

        OptionsReader opts   = new OptionsReader(context, args.length > 1 ? args[1] : null);
        this.maxNesting      = opts.getInt("max_nesting", DEFAULT_MAX_NESTING);
        this.allowNaN        = opts.getBool("allow_nan", false);
        this.symbolizeNames  = opts.getBool("symbolize_names", false);
        this.quirksMode      = opts.getBool("quirks_mode", false);
        this.createId        = opts.getString("create_id", getCreateId(context));
        this.createAdditions = opts.getBool("create_additions", true);
        this.objectClass     = opts.getClass("object_class", runtime.getHash());
        this.arrayClass      = opts.getClass("array_class", runtime.getArray());
        this.match_string    = opts.getHash("match_string");

        this.vSource = args[0].convertToString();
        if (!quirksMode) this.vSource = convertEncoding(context, vSource);

        return this;
    }

    /**
     * Checks the given string's encoding. If a non-UTF-8 encoding is detected,
     * a converted copy is returned.
     * Returns the source string if no conversion is needed.
     */
    private RubyString convertEncoding(ThreadContext context, RubyString source) {
        ByteList bl = source.getByteList();
        int len = bl.length();
        if (len < 2) {
            throw Utils.newException(context, Utils.M_PARSER_ERROR,
                "A JSON text must at least contain two octets!");
        }

        if (info.encodingsSupported()) {
            RubyEncoding encoding = (RubyEncoding)source.encoding(context);
            if (encoding != info.ascii8bit.get()) {
                return (RubyString)source.encode(context, info.utf8.get());
            }

            String sniffedEncoding = sniffByteList(bl);
            if (sniffedEncoding == null) return source; // assume UTF-8
            return reinterpretEncoding(context, source, sniffedEncoding);
        }

        String sniffedEncoding = sniffByteList(bl);
        if (sniffedEncoding == null) return source; // assume UTF-8
        Ruby runtime = context.getRuntime();
        return (RubyString)info.jsonModule.get().
            callMethod(context, "iconv",
                new IRubyObject[] {
                    runtime.newString("utf-8"),
                    runtime.newString(sniffedEncoding),
                    source});
    }

    /**
     * Checks the first four bytes of the given ByteList to infer its encoding,
     * using the principle demonstrated on section 3 of RFC 4627 (JSON).
     */
    private static String sniffByteList(ByteList bl) {
        if (bl.length() < 4) return null;
        if (bl.get(0) == 0 && bl.get(2) == 0) {
            return bl.get(1) == 0 ? "utf-32be" : "utf-16be";
        }
        if (bl.get(1) == 0 && bl.get(3) == 0) {
            return bl.get(2) == 0 ? "utf-32le" : "utf-16le";
        }
        return null;
    }

    /**
     * Assumes the given (binary) RubyString to be in the given encoding, then
     * converts it to UTF-8.
     */
    private RubyString reinterpretEncoding(ThreadContext context,
            RubyString str, String sniffedEncoding) {
        RubyEncoding actualEncoding = info.getEncoding(context, sniffedEncoding);
        RubyEncoding targetEncoding = info.utf8.get();
        RubyString dup = (RubyString)str.dup();
        dup.force_encoding(context, actualEncoding);
        return (RubyString)dup.encode_bang(context, targetEncoding);
    }

    /**
     * <code>Parser#parse()</code>
     *
     * <p>Parses the current JSON text <code>source</code> and returns the
     * complete data structure as a result.
     */
    @JRubyMethod
    public IRubyObject parse(ThreadContext context) {
        return new ParserSession(this, context).parse();
    }

    /**
     * <code>Parser#source()</code>
     *
     * <p>Returns a copy of the current <code>source</code> string, that was
     * used to construct this Parser.
     */
    @JRubyMethod(name = "source")
    public IRubyObject source_get() {
        return checkAndGetSource().dup();
    }

    /**
     * <code>Parser#quirks_mode?()</code>
     * 
     * <p>If set to <code>true</code>, if the parse is in quirks_mode, false
     * otherwise.
     */
    @JRubyMethod(name = "quirks_mode?")
    public IRubyObject quirks_mode_p(ThreadContext context) {
        return context.getRuntime().newBoolean(quirksMode);
    }

    public RubyString checkAndGetSource() {
      if (vSource != null) {
        return vSource;
      } else {
        throw getRuntime().newTypeError("uninitialized instance");
      }
    }

    /**
     * Queries <code>JSON.create_id</code>. Returns <code>null</code> if it is
     * set to <code>nil</code> or <code>false</code>, and a String if not.
     */
    private RubyString getCreateId(ThreadContext context) {
        IRubyObject v = info.jsonModule.get().callMethod(context, "create_id");
        return v.isTrue() ? v.convertToString() : null;
    }

    /**
     * A string parsing session.
     *
     * <p>Once a ParserSession is instantiated, the source string should not
     * change until the parsing is complete. The ParserSession object assumes
     * the source {@link RubyString} is still associated to its original
     * {@link ByteList}, which in turn must still be bound to the same
     * <code>byte[]</code> value (and on the same offset).
     */
    // Ragel uses lots of fall-through
    @SuppressWarnings("fallthrough")
    private static class ParserSession {
        private final Parser parser;
        private final ThreadContext context;
        private final ByteList byteList;
        private final ByteList view;
        private final byte[] data;
        private final StringDecoder decoder;
        private int currentNesting = 0;
        private final DoubleConverter dc;

        // initialization value for all state variables.
        // no idea about the origins of this value, ask Flori ;)
        private static final int EVIL = 0x666;

        private ParserSession(Parser parser, ThreadContext context) {
            this.parser = parser;
            this.context = context;
            this.byteList = parser.checkAndGetSource().getByteList();
            this.data = byteList.unsafeBytes();
            this.view = new ByteList(data, false);
            this.decoder = new StringDecoder(context);
            this.dc = new DoubleConverter();
        }

        private RaiseException unexpectedToken(int absStart, int absEnd) {
            RubyString msg = getRuntime().newString("unexpected token at '")
                    .cat(data, absStart, absEnd - absStart)
                    .cat((byte)'\'');
            return newException(Utils.M_PARSER_ERROR, msg);
        }

        private Ruby getRuntime() {
            return context.getRuntime();
        }

        %%{
            machine JSON_common;

            cr                  = '\n';
            cr_neg              = [^\n];
            ws                  = [ \t\r\n];
            c_comment           = '/*' ( any* - (any* '*/' any* ) ) '*/';
            cpp_comment         = '//' cr_neg* cr;
            comment             = c_comment | cpp_comment;
            ignore              = ws | comment;
            name_separator      = ':';
            value_separator     = ',';
            Vnull               = 'null';
            Vfalse              = 'false';
            Vtrue               = 'true';
            VNaN                = 'NaN';
            VInfinity           = 'Infinity';
            VMinusInfinity      = '-Infinity';
            begin_value         = [nft"\-[{NI] | digit;
            begin_object        = '{';
            end_object          = '}';
            begin_array         = '[';
            end_array           = ']';
            begin_string        = '"';
            begin_name          = begin_string;
            begin_number        = digit | '-';
        }%%

        %%{
            machine JSON_value;
            include JSON_common;

            write data;

            action parse_null {
                result = getRuntime().getNil();
            }
            action parse_false {
                result = getRuntime().getFalse();
            }
            action parse_true {
                result = getRuntime().getTrue();
            }
            action parse_nan {
                if (parser.allowNaN) {
                    result = getConstant(CONST_NAN);
                } else {
                    throw unexpectedToken(p - 2, pe);
                }
            }
            action parse_infinity {
                if (parser.allowNaN) {
                    result = getConstant(CONST_INFINITY);
                } else {
                    throw unexpectedToken(p - 7, pe);
                }
            }
            action parse_number {
                if (pe > fpc + 9 - (parser.quirksMode ? 1 : 0) &&
                    absSubSequence(fpc, fpc + 9).equals(JSON_MINUS_INFINITY)) {

                    if (parser.allowNaN) {
                        result = getConstant(CONST_MINUS_INFINITY);
                        fexec p + 10;
                        fhold;
                        fbreak;
                    } else {
                        throw unexpectedToken(p, pe);
                    }
                }
                parseFloat(res, fpc, pe);
                if (res.result != null) {
                    result = res.result;
                    fexec res.p;
                }
                parseInteger(res, fpc, pe);
                if (res.result != null) {
                    result = res.result;
                    fexec res.p;
                }
                fhold;
                fbreak;
            }
            action parse_string {
                parseString(res, fpc, pe);
                if (res.result == null) {
                    fhold;
                    fbreak;
                } else {
                    result = res.result;
                    fexec res.p;
                }
            }
            action parse_array {
                currentNesting++;
                parseArray(res, fpc, pe);
                currentNesting--;
                if (res.result == null) {
                    fhold;
                    fbreak;
                } else {
                    result = res.result;
                    fexec res.p;
                }
            }
            action parse_object {
                currentNesting++;
                parseObject(res, fpc, pe);
                currentNesting--;
                if (res.result == null) {
                    fhold;
                    fbreak;
                } else {
                    result = res.result;
                    fexec res.p;
                }
            }
            action exit {
                fhold;
                fbreak;
            }

            main := ( Vnull @parse_null |
                      Vfalse @parse_false |
                      Vtrue @parse_true |
                      VNaN @parse_nan |
                      VInfinity @parse_infinity |
                      begin_number >parse_number |
                      begin_string >parse_string |
                      begin_array >parse_array |
                      begin_object >parse_object
                    ) %*exit;
        }%%

        void parseValue(ParserResult res, int p, int pe) {
            int cs = EVIL;
            IRubyObject result = null;

            %% write init;
            %% write exec;

            if (cs >= JSON_value_first_final && result != null) {
                res.update(result, p);
            } else {
                res.update(null, p);
            }
        }

        %%{
            machine JSON_integer;

            write data;

            action exit {
                fhold;
                fbreak;
            }

            main := '-'? ( '0' | [1-9][0-9]* ) ( ^[0-9]? @exit );
        }%%

        void parseInteger(ParserResult res, int p, int pe) {
            int new_p = parseIntegerInternal(p, pe);
            if (new_p == -1) {
                res.update(null, p);
                return;
            }
            RubyInteger number = createInteger(p, new_p);
            res.update(number, new_p + 1);
            return;
        }

        int parseIntegerInternal(int p, int pe) {
            int cs = EVIL;

            %% write init;
            int memo = p;
            %% write exec;

            if (cs < JSON_integer_first_final) {
                return -1;
            }

            return p;
        }
        
        RubyInteger createInteger(int p, int new_p) {
            Ruby runtime = getRuntime();
            ByteList num = absSubSequence(p, new_p);
            return bytesToInum(runtime, num);
        }
        
        RubyInteger bytesToInum(Ruby runtime, ByteList num) {
            return runtime.is1_9() ?
                    ConvertBytes.byteListToInum19(runtime, num, 10, true) :
                    ConvertBytes.byteListToInum(runtime, num, 10, true);
        }

        %%{
            machine JSON_float;
            include JSON_common;

            write data;

            action exit {
                fhold;
                fbreak;
            }

            main := '-'?
                    ( ( ( '0' | [1-9][0-9]* ) '.' [0-9]+ ( [Ee] [+\-]?[0-9]+ )? )
                    | ( ( '0' | [1-9][0-9]* ) ( [Ee] [+\-]? [0-9]+ ) ) )
                    ( ^[0-9Ee.\-]? @exit );
        }%%

        void parseFloat(ParserResult res, int p, int pe) {
            int new_p = parseFloatInternal(p, pe);
            if (new_p == -1) {
                res.update(null, p);
                return;
            }
            RubyFloat number = createFloat(p, new_p);
            res.update(number, new_p + 1);
            return;
        }

        int parseFloatInternal(int p, int pe) {
            int cs = EVIL;

            %% write init;
            int memo = p;
            %% write exec;

            if (cs < JSON_float_first_final) {
                return -1;
            }
            
            return p;
        }
        
        RubyFloat createFloat(int p, int new_p) {
            Ruby runtime = getRuntime();
            ByteList num = absSubSequence(p, new_p);
            return RubyFloat.newFloat(runtime, dc.parse(num, true, runtime.is1_9()));
        }

        %%{
            machine JSON_string;
            include JSON_common;

            write data;

            action parse_string {
                int offset = byteList.begin();
                ByteList decoded = decoder.decode(byteList, memo + 1 - offset,
                                                  p - offset);
                result = getRuntime().newString(decoded);
                if (result == null) {
                    fhold;
                    fbreak;
                } else {
                    fexec p + 1;
                }
            }

            action exit {
                fhold;
                fbreak;
            }

            main := '"'
                    ( ( ^(["\\]|0..0x1f)
                      | '\\'["\\/bfnrt]
                      | '\\u'[0-9a-fA-F]{4}
                      | '\\'^(["\\/bfnrtu]|0..0x1f)
                      )* %parse_string
                    ) '"' @exit;
        }%%

        void parseString(ParserResult res, int p, int pe) {
            int cs = EVIL;
            IRubyObject result = null;

            %% write init;
            int memo = p;
            %% write exec;

            if (parser.createAdditions) {
                RubyHash match_string = parser.match_string;
                if (match_string != null) {
                    final IRubyObject[] memoArray = { result, null };
                    try {
                      match_string.visitAll(new RubyHash.Visitor() {
                          @Override
                          public void visit(IRubyObject pattern, IRubyObject klass) {
                              if (pattern.callMethod(context, "===", memoArray[0]).isTrue()) {
                                  memoArray[1] = klass;
                                  throw JumpException.SPECIAL_JUMP;
                              }
                          }
                      });
                    } catch (JumpException e) { }
                    if (memoArray[1] != null) {
                        RubyClass klass = (RubyClass) memoArray[1];
                        if (klass.respondsTo("json_creatable?") &&
                            klass.callMethod(context, "json_creatable?").isTrue()) {
                            result = klass.callMethod(context, "json_create", result);
                        }
                    }
                }
            }

            if (cs >= JSON_string_first_final && result != null) {
                res.update(result, p + 1);
            } else {
                res.update(null, p + 1);
            }
        }

        %%{
            machine JSON_array;
            include JSON_common;

            write data;

            action parse_value {
                parseValue(res, fpc, pe);
                if (res.result == null) {
                    fhold;
                    fbreak;
                } else {
                    if (parser.arrayClass == getRuntime().getArray()) {
                        ((RubyArray)result).append(res.result);
                    } else {
                        result.callMethod(context, "<<", res.result);
                    }
                    fexec res.p;
                }
            }

            action exit {
                fhold;
                fbreak;
            }

            next_element = value_separator ignore* begin_value >parse_value;

            main := begin_array
                    ignore*
                    ( ( begin_value >parse_value
                        ignore* )
                      ( ignore*
                        next_element
                        ignore* )* )?
                    ignore*
                    end_array @exit;
        }%%

        void parseArray(ParserResult res, int p, int pe) {
            int cs = EVIL;

            if (parser.maxNesting > 0 && currentNesting > parser.maxNesting) {
                throw newException(Utils.M_NESTING_ERROR,
                    "nesting of " + currentNesting + " is too deep");
            }

            IRubyObject result;
            if (parser.arrayClass == getRuntime().getArray()) {
                result = RubyArray.newArray(getRuntime());
            } else {
                result = parser.arrayClass.newInstance(context,
                        IRubyObject.NULL_ARRAY, Block.NULL_BLOCK);
            }

            %% write init;
            %% write exec;

            if (cs >= JSON_array_first_final) {
                res.update(result, p + 1);
            } else {
                throw unexpectedToken(p, pe);
            }
        }

        %%{
            machine JSON_object;
            include JSON_common;

            write data;

            action parse_value {
                parseValue(res, fpc, pe);
                if (res.result == null) {
                    fhold;
                    fbreak;
                } else {
                    if (parser.objectClass == getRuntime().getHash()) {
                        ((RubyHash)result).op_aset(context, lastName, res.result);
                    } else {
                        result.callMethod(context, "[]=", new IRubyObject[] { lastName, res.result });
                    }
                    fexec res.p;
                }
            }

            action parse_name {
                parseString(res, fpc, pe);
                if (res.result == null) {
                    fhold;
                    fbreak;
                } else {
                    RubyString name = (RubyString)res.result;
                    if (parser.symbolizeNames) {
                        lastName = context.getRuntime().is1_9()
                                       ? name.intern19()
                                       : name.intern();
                    } else {
                        lastName = name;
                    }
                    fexec res.p;
                }
            }

            action exit {
                fhold;
                fbreak;
            }
            
            pair      = ignore* begin_name >parse_name ignore* name_separator
              ignore* begin_value >parse_value;
            next_pair = ignore* value_separator pair;

            main := (
              begin_object (pair (next_pair)*)? ignore* end_object
            ) @exit;
        }%%

        void parseObject(ParserResult res, int p, int pe) {
            int cs = EVIL;
            IRubyObject lastName = null;
            boolean objectDefault = true;

            if (parser.maxNesting > 0 && currentNesting > parser.maxNesting) {
                throw newException(Utils.M_NESTING_ERROR,
                    "nesting of " + currentNesting + " is too deep");
            }

            // this is guaranteed to be a RubyHash due to the earlier
            // allocator test at OptionsReader#getClass
            IRubyObject result;
            if (parser.objectClass == getRuntime().getHash()) {
                result = RubyHash.newHash(getRuntime());
            } else {
                objectDefault = false;
                result = parser.objectClass.newInstance(context,
                        IRubyObject.NULL_ARRAY, Block.NULL_BLOCK);
            }

            %% write init;
            %% write exec;

            if (cs < JSON_object_first_final) {
                res.update(null, p + 1);
                return;
            }

            IRubyObject returnedResult = result;

            // attempt to de-serialize object
            if (parser.createAdditions) {
                IRubyObject vKlassName;
                if (objectDefault) {
                    vKlassName = ((RubyHash)result).op_aref(context, parser.createId);
                } else {
                    vKlassName = result.callMethod(context, "[]", parser.createId);
                }

                if (!vKlassName.isNil()) {
                    // might throw ArgumentError, we let it propagate
                    IRubyObject klass = parser.info.jsonModule.get().
                            callMethod(context, "deep_const_get", vKlassName);
                    if (klass.respondsTo("json_creatable?") &&
                        klass.callMethod(context, "json_creatable?").isTrue()) {

                        returnedResult = klass.callMethod(context, "json_create", result);
                    }
                }
            }
            res.update(returnedResult, p + 1);
        }

        %%{
            machine JSON;
            include JSON_common;

            write data;

            action parse_object {
                currentNesting = 1;
                parseObject(res, fpc, pe);
                if (res.result == null) {
                    fhold;
                    fbreak;
                } else {
                    result = res.result;
                    fexec res.p;
                }
            }

            action parse_array {
                currentNesting = 1;
                parseArray(res, fpc, pe);
                if (res.result == null) {
                    fhold;
                    fbreak;
                } else {
                    result = res.result;
                    fexec res.p;
                }
            }

            main := ignore*
                    ( begin_object >parse_object
                    | begin_array >parse_array )
                    ignore*;
        }%%

        public IRubyObject parseStrict() {
            int cs = EVIL;
            int p, pe;
            IRubyObject result = null;
            ParserResult res = new ParserResult();

            %% write init;
            p = byteList.begin();
            pe = p + byteList.length();
            %% write exec;

            if (cs >= JSON_first_final && p == pe) {
                return result;
            } else {
                throw unexpectedToken(p, pe);
            }
        }

        %%{
            machine JSON_quirks_mode;
            include JSON_common;

            write data;

            action parse_value {
                parseValue(res, fpc, pe);
                if (res.result == null) {
                    fhold;
                    fbreak;
                } else {
                    result = res.result;
                    fexec res.p;
                }
            }

            main := ignore*
                    ( begin_value >parse_value)
                    ignore*;
        }%%

        public IRubyObject parseQuirksMode() {
            int cs = EVIL;
            int p, pe;
            IRubyObject result = null;
            ParserResult res = new ParserResult();

            %% write init;
            p = byteList.begin();
            pe = p + byteList.length();
            %% write exec;

            if (cs >= JSON_quirks_mode_first_final && p == pe) {
                return result;
            } else {
                throw unexpectedToken(p, pe);
            }
        }

        public IRubyObject parse() {
          if (parser.quirksMode) {
            return parseQuirksMode();
          } else {
            return parseStrict();
          }

        }

        /**
         * Updates the "view" bytelist with the new offsets and returns it.
         * @param start
         * @param end
         */
        private ByteList absSubSequence(int absStart, int absEnd) {
            view.setBegin(absStart);
            view.setRealSize(absEnd - absStart);
            return view;
        }

        /**
         * Retrieves a constant directly descended from the <code>JSON</code> module.
         * @param name The constant name
         */
        private IRubyObject getConstant(String name) {
            return parser.info.jsonModule.get().getConstant(name);
        }

        private RaiseException newException(String className, String message) {
            return Utils.newException(context, className, message);
        }

        private RaiseException newException(String className, RubyString message) {
            return Utils.newException(context, className, message);
        }

        private RaiseException newException(String className,
                String messageBegin, ByteList messageEnd) {
            return newException(className,
                    getRuntime().newString(messageBegin).cat(messageEnd));
        }
    }
}
