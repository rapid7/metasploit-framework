/*
 * This code is copyrighted work by Daniel Luz <dev at mernen dot com>.
 *
 * Distributed under the Ruby and GPLv2 licenses; see COPYING and GPL files
 * for details.
 */
package json.ext;

import org.jruby.Ruby;
import org.jruby.RubyBoolean;
import org.jruby.RubyClass;
import org.jruby.RubyHash;
import org.jruby.RubyInteger;
import org.jruby.RubyNumeric;
import org.jruby.RubyObject;
import org.jruby.RubyString;
import org.jruby.anno.JRubyMethod;
import org.jruby.runtime.Block;
import org.jruby.runtime.ObjectAllocator;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.Visibility;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;

/**
 * The <code>JSON::Ext::Generator::State</code> class.
 *
 * <p>This class is used to create State instances, that are use to hold data
 * while generating a JSON text from a a Ruby data structure.
 *
 * @author mernen
 */
public class GeneratorState extends RubyObject {
    /**
     * The indenting unit string. Will be repeated several times for larger
     * indenting levels.
     */
    private ByteList indent = ByteList.EMPTY_BYTELIST;
    /**
     * The spacing to be added after a semicolon on a JSON object.
     * @see #spaceBefore
     */
    private ByteList space = ByteList.EMPTY_BYTELIST;
    /**
     * The spacing to be added before a semicolon on a JSON object.
     * @see #space
     */
    private ByteList spaceBefore = ByteList.EMPTY_BYTELIST;
    /**
     * Any suffix to be added after the comma for each element on a JSON object.
     * It is assumed to be a newline, if set.
     */
    private ByteList objectNl = ByteList.EMPTY_BYTELIST;
    /**
     * Any suffix to be added after the comma for each element on a JSON Array.
     * It is assumed to be a newline, if set.
     */
    private ByteList arrayNl = ByteList.EMPTY_BYTELIST;

    /**
     * The maximum level of nesting of structures allowed.
     * <code>0</code> means disabled.
     */
    private int maxNesting = DEFAULT_MAX_NESTING;
    static final int DEFAULT_MAX_NESTING = 19;
    /**
     * Whether special float values (<code>NaN</code>, <code>Infinity</code>,
     * <code>-Infinity</code>) are accepted.
     * If set to <code>false</code>, an exception will be thrown upon
     * encountering one.
     */
    private boolean allowNaN = DEFAULT_ALLOW_NAN;
    static final boolean DEFAULT_ALLOW_NAN = false;
    /**
     * If set to <code>true</code> all JSON documents generated do not contain
     * any other characters than ASCII characters.
     */
    private boolean asciiOnly = DEFAULT_ASCII_ONLY;
    static final boolean DEFAULT_ASCII_ONLY = false;
    /**
     * If set to <code>true</code> all JSON values generated might not be
     * RFC-conform JSON documents.
     */
    private boolean quirksMode = DEFAULT_QUIRKS_MODE;
    static final boolean DEFAULT_QUIRKS_MODE = false;
    /**
     * The initial buffer length of this state. (This isn't really used on all
     * non-C implementations.)
     */
    private int bufferInitialLength = DEFAULT_BUFFER_INITIAL_LENGTH;
    static final int DEFAULT_BUFFER_INITIAL_LENGTH = 1024;

    /**
     * The current depth (inside a #to_json call)
     */
    private int depth = 0;

    static final ObjectAllocator ALLOCATOR = new ObjectAllocator() {
        public IRubyObject allocate(Ruby runtime, RubyClass klazz) {
            return new GeneratorState(runtime, klazz);
        }
    };

    public GeneratorState(Ruby runtime, RubyClass metaClass) {
        super(runtime, metaClass);
    }

    /**
     * <code>State.from_state(opts)</code>
     *
     * <p>Creates a State object from <code>opts</code>, which ought to be
     * {@link RubyHash Hash} to create a new <code>State</code> instance
     * configured by <codes>opts</code>, something else to create an
     * unconfigured instance. If <code>opts</code> is a <code>State</code>
     * object, it is just returned.
     * @param clazzParam The receiver of the method call
     *                   ({@link RubyClass} <code>State</code>)
     * @param opts The object to use as a base for the new <code>State</code>
     * @param block The block passed to the method
     * @return A <code>GeneratorState</code> as determined above
     */
    @JRubyMethod(meta=true)
    public static IRubyObject from_state(ThreadContext context,
            IRubyObject klass, IRubyObject opts) {
        return fromState(context, opts);
    }

    static GeneratorState fromState(ThreadContext context, IRubyObject opts) {
        return fromState(context, RuntimeInfo.forRuntime(context.getRuntime()), opts);
    }

    static GeneratorState fromState(ThreadContext context, RuntimeInfo info,
                                    IRubyObject opts) {
        RubyClass klass = info.generatorStateClass.get();
        if (opts != null) {
            // if the given parameter is a Generator::State, return itself
            if (klass.isInstance(opts)) return (GeneratorState)opts;

            // if the given parameter is a Hash, pass it to the instantiator
            if (context.getRuntime().getHash().isInstance(opts)) {
                return (GeneratorState)klass.newInstance(context,
                        new IRubyObject[] {opts}, Block.NULL_BLOCK);
            }
        }

        // for other values, return the safe prototype
        return (GeneratorState)info.getSafeStatePrototype(context).dup();
    }

    /**
     * <code>State#initialize(opts = {})</code>
     *
     * Instantiates a new <code>State</code> object, configured by <code>opts</code>.
     *
     * <code>opts</code> can have the following keys:
     *
     * <dl>
     * <dt><code>:indent</code>
     * <dd>a {@link RubyString String} used to indent levels (default: <code>""</code>)
     * <dt><code>:space</code>
     * <dd>a String that is put after a <code>':'</code> or <code>','</code>
     * delimiter (default: <code>""</code>)
     * <dt><code>:space_before</code>
     * <dd>a String that is put before a <code>":"</code> pair delimiter
     * (default: <code>""</code>)
     * <dt><code>:object_nl</code>
     * <dd>a String that is put at the end of a JSON object (default: <code>""</code>)
     * <dt><code>:array_nl</code>
     * <dd>a String that is put at the end of a JSON array (default: <code>""</code>)
     * <dt><code>:allow_nan</code>
     * <dd><code>true</code> if <code>NaN</code>, <code>Infinity</code>, and
     * <code>-Infinity</code> should be generated, otherwise an exception is
     * thrown if these values are encountered.
     * This options defaults to <code>false</code>.
     */
    @JRubyMethod(optional=1, visibility=Visibility.PRIVATE)
    public IRubyObject initialize(ThreadContext context, IRubyObject[] args) {
        configure(context, args.length > 0 ? args[0] : null);
        return this;
    }

    @JRubyMethod
    public IRubyObject initialize_copy(ThreadContext context, IRubyObject vOrig) {
        Ruby runtime = context.getRuntime();
        if (!(vOrig instanceof GeneratorState)) {
            throw runtime.newTypeError(vOrig, getType());
        }
        GeneratorState orig = (GeneratorState)vOrig;
        this.indent = orig.indent;
        this.space = orig.space;
        this.spaceBefore = orig.spaceBefore;
        this.objectNl = orig.objectNl;
        this.arrayNl = orig.arrayNl;
        this.maxNesting = orig.maxNesting;
        this.allowNaN = orig.allowNaN;
        this.asciiOnly = orig.asciiOnly;
        this.quirksMode = orig.quirksMode;
        this.bufferInitialLength = orig.bufferInitialLength;
        this.depth = orig.depth;
        return this;
    }

    /**
     * Generates a valid JSON document from object <code>obj</code> and returns
     * the result. If no valid JSON document can be created this method raises
     * a GeneratorError exception.
     */
    @JRubyMethod
    public IRubyObject generate(ThreadContext context, IRubyObject obj) {
        RubyString result = Generator.generateJson(context, obj, this);
        if (!quirksMode && !objectOrArrayLiteral(result)) {
            throw Utils.newException(context, Utils.M_GENERATOR_ERROR,
                    "only generation of JSON objects or arrays allowed");
        }
        return result;
    }

    /**
     * Ensures the given string is in the form "[...]" or "{...}", being
     * possibly surrounded by white space.
     * The string's encoding must be ASCII-compatible.
     * @param value
     * @return
     */
    private static boolean objectOrArrayLiteral(RubyString value) {
        ByteList bl = value.getByteList();
        int len = bl.length();

        for (int pos = 0; pos < len - 1; pos++) {
            int b = bl.get(pos);
            if (Character.isWhitespace(b)) continue;

            // match the opening brace
            switch (b) {
            case '[':
                return matchClosingBrace(bl, pos, len, ']');
            case '{':
                return matchClosingBrace(bl, pos, len, '}');
            default:
                return false;
            }
        }
        return false;
    }

    private static boolean matchClosingBrace(ByteList bl, int pos, int len,
                                             int brace) {
        for (int endPos = len - 1; endPos > pos; endPos--) {
            int b = bl.get(endPos);
            if (Character.isWhitespace(b)) continue;
            return b == brace;
        }
        return false;
    }

    @JRubyMethod(name="[]", required=1)
    public IRubyObject op_aref(ThreadContext context, IRubyObject vName) {
        String name = vName.asJavaString();
        if (getMetaClass().isMethodBound(name, true)) {
            return send(context, vName, Block.NULL_BLOCK);
        }
        return context.getRuntime().getNil();
    }

    public ByteList getIndent() {
        return indent;
    }

    @JRubyMethod(name="indent")
    public RubyString indent_get(ThreadContext context) {
        return context.getRuntime().newString(indent);
    }

    @JRubyMethod(name="indent=")
    public IRubyObject indent_set(ThreadContext context, IRubyObject indent) {
        this.indent = prepareByteList(context, indent);
        return indent;
    }

    public ByteList getSpace() {
        return space;
    }

    @JRubyMethod(name="space")
    public RubyString space_get(ThreadContext context) {
        return context.getRuntime().newString(space);
    }

    @JRubyMethod(name="space=")
    public IRubyObject space_set(ThreadContext context, IRubyObject space) {
        this.space = prepareByteList(context, space);
        return space;
    }

    public ByteList getSpaceBefore() {
        return spaceBefore;
    }

    @JRubyMethod(name="space_before")
    public RubyString space_before_get(ThreadContext context) {
        return context.getRuntime().newString(spaceBefore);
    }

    @JRubyMethod(name="space_before=")
    public IRubyObject space_before_set(ThreadContext context,
                                        IRubyObject spaceBefore) {
        this.spaceBefore = prepareByteList(context, spaceBefore);
        return spaceBefore;
    }

    public ByteList getObjectNl() {
        return objectNl;
    }

    @JRubyMethod(name="object_nl")
    public RubyString object_nl_get(ThreadContext context) {
        return context.getRuntime().newString(objectNl);
    }

    @JRubyMethod(name="object_nl=")
    public IRubyObject object_nl_set(ThreadContext context,
                                     IRubyObject objectNl) {
        this.objectNl = prepareByteList(context, objectNl);
        return objectNl;
    }

    public ByteList getArrayNl() {
        return arrayNl;
    }

    @JRubyMethod(name="array_nl")
    public RubyString array_nl_get(ThreadContext context) {
        return context.getRuntime().newString(arrayNl);
    }

    @JRubyMethod(name="array_nl=")
    public IRubyObject array_nl_set(ThreadContext context,
                                    IRubyObject arrayNl) {
        this.arrayNl = prepareByteList(context, arrayNl);
        return arrayNl;
    }

    @JRubyMethod(name="check_circular?")
    public RubyBoolean check_circular_p(ThreadContext context) {
        return context.getRuntime().newBoolean(maxNesting != 0);
    }

    /**
     * Returns the maximum level of nesting configured for this state.
     */
    public int getMaxNesting() {
        return maxNesting;
    }

    @JRubyMethod(name="max_nesting")
    public RubyInteger max_nesting_get(ThreadContext context) {
        return context.getRuntime().newFixnum(maxNesting);
    }

    @JRubyMethod(name="max_nesting=")
    public IRubyObject max_nesting_set(IRubyObject max_nesting) {
        maxNesting = RubyNumeric.fix2int(max_nesting);
        return max_nesting;
    }

    public boolean allowNaN() {
        return allowNaN;
    }

    @JRubyMethod(name="allow_nan?")
    public RubyBoolean allow_nan_p(ThreadContext context) {
        return context.getRuntime().newBoolean(allowNaN);
    }

    public boolean asciiOnly() {
        return asciiOnly;
    }

    @JRubyMethod(name="ascii_only?")
    public RubyBoolean ascii_only_p(ThreadContext context) {
        return context.getRuntime().newBoolean(asciiOnly);
    }

    @JRubyMethod(name="quirks_mode")
    public RubyBoolean quirks_mode_get(ThreadContext context) {
        return context.getRuntime().newBoolean(quirksMode);
    }

    @JRubyMethod(name="quirks_mode=")
    public IRubyObject quirks_mode_set(IRubyObject quirks_mode) {
        quirksMode = quirks_mode.isTrue();
        return quirks_mode.getRuntime().newBoolean(quirksMode);
    }

    @JRubyMethod(name="buffer_initial_length")
    public RubyInteger buffer_initial_length_get(ThreadContext context) {
        return context.getRuntime().newFixnum(bufferInitialLength);
    }

    @JRubyMethod(name="buffer_initial_length=")
    public IRubyObject buffer_initial_length_set(IRubyObject buffer_initial_length) {
        int newLength = RubyNumeric.fix2int(buffer_initial_length);
        if (newLength > 0) bufferInitialLength = newLength;
        return buffer_initial_length;
    }

    @JRubyMethod(name="quirks_mode?")
    public RubyBoolean quirks_mode_p(ThreadContext context) {
        return context.getRuntime().newBoolean(quirksMode);
    }

    public int getDepth() {
        return depth;
    }

    @JRubyMethod(name="depth")
    public RubyInteger depth_get(ThreadContext context) {
        return context.getRuntime().newFixnum(depth);
    }

    @JRubyMethod(name="depth=")
    public IRubyObject depth_set(IRubyObject vDepth) {
        depth = RubyNumeric.fix2int(vDepth);
        return vDepth;
    }

    private ByteList prepareByteList(ThreadContext context, IRubyObject value) {
        RubyString str = value.convertToString();
        RuntimeInfo info = RuntimeInfo.forRuntime(context.getRuntime());
        if (info.encodingsSupported() && str.encoding(context) != info.utf8.get()) {
            str = (RubyString)str.encode(context, info.utf8.get());
        }
        return str.getByteList().dup();
    }

    /**
     * <code>State#configure(opts)</code>
     *
     * <p>Configures this State instance with the {@link RubyHash Hash}
     * <code>opts</code>, and returns itself.
     * @param vOpts The options hash
     * @return The receiver
     */
    @JRubyMethod
    public IRubyObject configure(ThreadContext context, IRubyObject vOpts) {
        OptionsReader opts = new OptionsReader(context, vOpts);

        ByteList indent = opts.getString("indent");
        if (indent != null) this.indent = indent;

        ByteList space = opts.getString("space");
        if (space != null) this.space = space;

        ByteList spaceBefore = opts.getString("space_before");
        if (spaceBefore != null) this.spaceBefore = spaceBefore;

        ByteList arrayNl = opts.getString("array_nl");
        if (arrayNl != null) this.arrayNl = arrayNl;

        ByteList objectNl = opts.getString("object_nl");
        if (objectNl != null) this.objectNl = objectNl;

        maxNesting = opts.getInt("max_nesting", DEFAULT_MAX_NESTING);
        allowNaN   = opts.getBool("allow_nan",  DEFAULT_ALLOW_NAN);
        asciiOnly  = opts.getBool("ascii_only", DEFAULT_ASCII_ONLY);
        quirksMode = opts.getBool("quirks_mode", DEFAULT_QUIRKS_MODE);
        bufferInitialLength = opts.getInt("buffer_initial_length", DEFAULT_BUFFER_INITIAL_LENGTH);

        depth = opts.getInt("depth", 0);

        return this;
    }

    /**
     * <code>State#to_h()</code>
     *
     * <p>Returns the configuration instance variables as a hash, that can be
     * passed to the configure method.
     * @return
     */
    @JRubyMethod
    public RubyHash to_h(ThreadContext context) {
        Ruby runtime = context.getRuntime();
        RubyHash result = RubyHash.newHash(runtime);

        result.op_aset(context, runtime.newSymbol("indent"), indent_get(context));
        result.op_aset(context, runtime.newSymbol("space"), space_get(context));
        result.op_aset(context, runtime.newSymbol("space_before"), space_before_get(context));
        result.op_aset(context, runtime.newSymbol("object_nl"), object_nl_get(context));
        result.op_aset(context, runtime.newSymbol("array_nl"), array_nl_get(context));
        result.op_aset(context, runtime.newSymbol("allow_nan"), allow_nan_p(context));
        result.op_aset(context, runtime.newSymbol("ascii_only"), ascii_only_p(context));
        result.op_aset(context, runtime.newSymbol("quirks_mode"), quirks_mode_p(context));
        result.op_aset(context, runtime.newSymbol("max_nesting"), max_nesting_get(context));
        result.op_aset(context, runtime.newSymbol("depth"), depth_get(context));
        result.op_aset(context, runtime.newSymbol("buffer_initial_length"), buffer_initial_length_get(context));
        return result;
    }

    public int increaseDepth() {
        depth++;
        checkMaxNesting();
        return depth;
    }

    public int decreaseDepth() {
        return --depth;
    }

    /**
     * Checks if the current depth is allowed as per this state's options.
     * @param context
     * @param depth The corrent depth
     */
    private void checkMaxNesting() {
        if (maxNesting != 0 && depth > maxNesting) {
            depth--;
            throw Utils.newException(getRuntime().getCurrentContext(),
                    Utils.M_NESTING_ERROR, "nesting of " + depth + " is too deep");
        }
    }
}
