/*
 * This code is copyrighted work by Daniel Luz <dev at mernen dot com>.
 *
 * Distributed under the Ruby and GPLv2 licenses; see COPYING and GPL files
 * for details.
 */
package json.ext;

import java.lang.ref.WeakReference;
import java.util.HashMap;
import java.util.Map;
import java.util.WeakHashMap;
import org.jruby.Ruby;
import org.jruby.RubyClass;
import org.jruby.RubyEncoding;
import org.jruby.RubyModule;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;


final class RuntimeInfo {
    // since the vast majority of cases runs just one runtime,
    // we optimize for that
    private static WeakReference<Ruby> runtime1 = new WeakReference<Ruby>(null);
    private static RuntimeInfo info1;
    // store remaining runtimes here (does not include runtime1)
    private static Map<Ruby, RuntimeInfo> runtimes;

    // these fields are filled by the service loaders
    // Use WeakReferences so that RuntimeInfo doesn't indirectly hold a hard reference to
    // the Ruby runtime object, which would cause memory leaks in the runtimes map above.
    /** JSON */
    WeakReference<RubyModule> jsonModule;
    /** JSON::Ext::Generator::GeneratorMethods::String::Extend */
    WeakReference<RubyModule> stringExtendModule;
    /** JSON::Ext::Generator::State */
    WeakReference<RubyClass> generatorStateClass;
    /** JSON::SAFE_STATE_PROTOTYPE */
    WeakReference<GeneratorState> safeStatePrototype;

    final WeakReference<RubyEncoding> utf8;
    final WeakReference<RubyEncoding> ascii8bit;
    // other encodings
    private final Map<String, WeakReference<RubyEncoding>> encodings;

    private RuntimeInfo(Ruby runtime) {
        RubyClass encodingClass = runtime.getEncoding();
        if (encodingClass == null) { // 1.8 mode
            utf8 = ascii8bit = null;
            encodings = null;
        } else {
            ThreadContext context = runtime.getCurrentContext();

            utf8 = new WeakReference<RubyEncoding>((RubyEncoding)RubyEncoding.find(context,
                    encodingClass, runtime.newString("utf-8")));
            ascii8bit = new WeakReference<RubyEncoding>((RubyEncoding)RubyEncoding.find(context,
                    encodingClass, runtime.newString("ascii-8bit")));
            encodings = new HashMap<String, WeakReference<RubyEncoding>>();
        }
    }

    static RuntimeInfo initRuntime(Ruby runtime) {
        synchronized (RuntimeInfo.class) {
            if (runtime1.get() == runtime) {
                return info1;
            } else if (runtime1.get() == null) {
                runtime1 = new WeakReference<Ruby>(runtime);
                info1 = new RuntimeInfo(runtime);
                return info1;
            } else {
                if (runtimes == null) {
                    runtimes = new WeakHashMap<Ruby, RuntimeInfo>(1);
                }
                RuntimeInfo cache = runtimes.get(runtime);
                if (cache == null) {
                    cache = new RuntimeInfo(runtime);
                    runtimes.put(runtime, cache);
                }
                return cache;
            }
        }
    }

    public static RuntimeInfo forRuntime(Ruby runtime) {
        synchronized (RuntimeInfo.class) {
            if (runtime1.get() == runtime) return info1;
            RuntimeInfo cache = null;
            if (runtimes != null) cache = runtimes.get(runtime);
            assert cache != null : "Runtime given has not initialized JSON::Ext";
            return cache;
        }
    }

    public boolean encodingsSupported() {
        return utf8 != null && utf8.get() != null;
    }

    public RubyEncoding getEncoding(ThreadContext context, String name) {
        synchronized (encodings) {
            WeakReference<RubyEncoding> encoding = encodings.get(name);
            if (encoding == null) {
                Ruby runtime = context.getRuntime();
                encoding = new WeakReference<RubyEncoding>((RubyEncoding)RubyEncoding.find(context,
                        runtime.getEncoding(), runtime.newString(name)));
                encodings.put(name, encoding);
            }
            return encoding.get();
        }
    }

    public GeneratorState getSafeStatePrototype(ThreadContext context) {
        if (safeStatePrototype == null) {
            IRubyObject value = jsonModule.get().getConstant("SAFE_STATE_PROTOTYPE");
            if (!(value instanceof GeneratorState)) {
                throw context.getRuntime().newTypeError(value, generatorStateClass.get());
            }
            safeStatePrototype = new WeakReference<GeneratorState>((GeneratorState)value);
        }
        return safeStatePrototype.get();
    }
}
