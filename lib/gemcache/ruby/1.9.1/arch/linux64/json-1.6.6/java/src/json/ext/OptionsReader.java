/*
 * This code is copyrighted work by Daniel Luz <dev at mernen dot com>.
 *
 * Distributed under the Ruby and GPLv2 licenses; see COPYING and GPL files
 * for details.
 */
package json.ext;

import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyHash;
import org.jruby.RubyNumeric;
import org.jruby.RubyString;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;

final class OptionsReader {
    private final ThreadContext context;
    private final Ruby runtime;
    private final RubyHash opts;
    private RuntimeInfo info;

    OptionsReader(ThreadContext context, IRubyObject vOpts) {
        this.context = context;
        this.runtime = context.getRuntime();

        if (vOpts == null || vOpts.isNil()) {
            opts = null;
        } else if (vOpts.respondsTo("to_hash")) {
            opts = vOpts.convertToHash();
        } else {
            opts = vOpts.callMethod(context, "to_h").convertToHash();
        }
    }

    private RuntimeInfo getRuntimeInfo() {
        if (info != null) return info;
        info = RuntimeInfo.forRuntime(runtime);
        return info;
    }

    /**
     * Efficiently looks up items with a {@link RubySymbol Symbol} key
     * @param key The Symbol name to look up for
     * @return The item in the {@link RubyHash Hash}, or <code>null</code>
     *         if not found
     */
    IRubyObject get(String key) {
        return opts == null ? null : opts.fastARef(runtime.newSymbol(key));
    }

    boolean getBool(String key, boolean defaultValue) {
        IRubyObject value = get(key);
        return value == null ? defaultValue : value.isTrue();
    }

    int getInt(String key, int defaultValue) {
        IRubyObject value = get(key);
        if (value == null) return defaultValue;
        if (!value.isTrue()) return 0;
        return RubyNumeric.fix2int(value);
    }

    /**
     * Reads the setting from the options hash. If no entry is set for this
     * key or if it evaluates to <code>false</code>, returns null; attempts to
     * coerce the value to {@link RubyString String} otherwise.
     * @param key The Symbol name to look up for
     * @return <code>null</code> if the key is not in the Hash or if
     *         its value evaluates to <code>false</code>
     * @throws RaiseException <code>TypeError</code> if the value does not
     *                        evaluate to <code>false</code> and can't be
     *                        converted to string
     */
    ByteList getString(String key) {
        RubyString str = getString(key, null);
        return str == null ? null : str.getByteList().dup();
    }

    RubyString getString(String key, RubyString defaultValue) {
        IRubyObject value = get(key);
        if (value == null || !value.isTrue()) return defaultValue;

        RubyString str = value.convertToString();
        RuntimeInfo info = getRuntimeInfo();
        if (info.encodingsSupported() && str.encoding(context) != info.utf8.get()) {
            str = (RubyString)str.encode(context, info.utf8.get());
        }
        return str;
    }

    /**
     * Reads the setting from the options hash. If it is <code>nil</code> or
     * undefined, returns the default value given.
     * If not, ensures it is a RubyClass instance and shares the same
     * allocator as the default value (i.e. for the basic types which have
     * their specific allocators, this ensures the passed value is
     * a subclass of them).
     */
    RubyClass getClass(String key, RubyClass defaultValue) {
        IRubyObject value = get(key);

        if (value == null || value.isNil()) return defaultValue;
        return (RubyClass)value;
    }

    public RubyHash getHash(String key) {
        IRubyObject value = get(key);
        if (value == null || value.isNil()) return new RubyHash(runtime);
        return (RubyHash) value;
    }
}
