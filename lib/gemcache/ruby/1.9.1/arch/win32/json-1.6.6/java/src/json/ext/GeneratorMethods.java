/*
 * This code is copyrighted work by Daniel Luz <dev at mernen dot com>.
 *
 * Distributed under the Ruby and GPLv2 licenses; see COPYING and GPL files
 * for details.
 */
package json.ext;

import java.lang.ref.WeakReference;
import org.jruby.Ruby;
import org.jruby.RubyArray;
import org.jruby.RubyBoolean;
import org.jruby.RubyFixnum;
import org.jruby.RubyFloat;
import org.jruby.RubyHash;
import org.jruby.RubyInteger;
import org.jruby.RubyModule;
import org.jruby.RubyNumeric;
import org.jruby.RubyString;
import org.jruby.anno.JRubyMethod;
import org.jruby.runtime.ThreadContext;
import org.jruby.runtime.builtin.IRubyObject;
import org.jruby.util.ByteList;

/**
 * A class that populates the
 * <code>Json::Ext::Generator::GeneratorMethods</code> module.
 *
 * @author mernen
 */
class GeneratorMethods {
    /**
     * Populates the given module with all modules and their methods
     * @param info
     * @param generatorMethodsModule The module to populate
     * (normally <code>JSON::Generator::GeneratorMethods</code>)
     */
    static void populate(RuntimeInfo info, RubyModule module) {
        defineMethods(module, "Array",      RbArray.class);
        defineMethods(module, "FalseClass", RbFalse.class);
        defineMethods(module, "Float",      RbFloat.class);
        defineMethods(module, "Hash",       RbHash.class);
        defineMethods(module, "Integer",    RbInteger.class);
        defineMethods(module, "NilClass",   RbNil.class);
        defineMethods(module, "Object",     RbObject.class);
        defineMethods(module, "String",     RbString.class);
        defineMethods(module, "TrueClass",  RbTrue.class);

        info.stringExtendModule = new WeakReference<RubyModule>(module.defineModuleUnder("String")
                                            .defineModuleUnder("Extend"));
        info.stringExtendModule.get().defineAnnotatedMethods(StringExtend.class);
    }

    /**
     * Convenience method for defining methods on a submodule.
     * @param parentModule
     * @param submoduleName
     * @param klass
     */
    private static void defineMethods(RubyModule parentModule,
            String submoduleName, Class klass) {
        RubyModule submodule = parentModule.defineModuleUnder(submoduleName);
        submodule.defineAnnotatedMethods(klass);
    }


    public static class RbHash {
        @JRubyMethod(rest=true)
        public static IRubyObject to_json(ThreadContext context,
                IRubyObject vSelf, IRubyObject[] args) {
            return Generator.generateJson(context, (RubyHash)vSelf,
                    Generator.HASH_HANDLER, args);
        }
    }

    public static class RbArray {
        @JRubyMethod(rest=true)
        public static IRubyObject to_json(ThreadContext context,
                IRubyObject vSelf, IRubyObject[] args) {
            return Generator.generateJson(context, (RubyArray)vSelf,
                    Generator.ARRAY_HANDLER, args);
        }
    }

    public static class RbInteger {
        @JRubyMethod(rest=true)
        public static IRubyObject to_json(ThreadContext context,
                IRubyObject vSelf, IRubyObject[] args) {
            return Generator.generateJson(context, vSelf, args);
        }
    }

    public static class RbFloat {
        @JRubyMethod(rest=true)
        public static IRubyObject to_json(ThreadContext context,
                IRubyObject vSelf, IRubyObject[] args) {
            return Generator.generateJson(context, (RubyFloat)vSelf,
                    Generator.FLOAT_HANDLER, args);
        }
    }

    public static class RbString {
        @JRubyMethod(rest=true)
        public static IRubyObject to_json(ThreadContext context,
                IRubyObject vSelf, IRubyObject[] args) {
            return Generator.generateJson(context, (RubyString)vSelf,
                    Generator.STRING_HANDLER, args);
        }

        /**
         * <code>{@link RubyString String}#to_json_raw(*)</code>
         *
         * <p>This method creates a JSON text from the result of a call to
         * {@link #to_json_raw_object} of this String.
         */
        @JRubyMethod(rest=true)
        public static IRubyObject to_json_raw(ThreadContext context,
                IRubyObject vSelf, IRubyObject[] args) {
            RubyHash obj = toJsonRawObject(context, Utils.ensureString(vSelf));
            return Generator.generateJson(context, obj,
                    Generator.HASH_HANDLER, args);
        }

        /**
         * <code>{@link RubyString String}#to_json_raw_object(*)</code>
         *
         * <p>This method creates a raw object Hash, that can be nested into
         * other data structures and will be unparsed as a raw string. This
         * method should be used if you want to convert raw strings to JSON
         * instead of UTF-8 strings, e.g. binary data.
         */
        @JRubyMethod(rest=true)
        public static IRubyObject to_json_raw_object(ThreadContext context,
                IRubyObject vSelf, IRubyObject[] args) {
            return toJsonRawObject(context, Utils.ensureString(vSelf));
        }

        private static RubyHash toJsonRawObject(ThreadContext context,
                                                RubyString self) {
            Ruby runtime = context.getRuntime();
            RubyHash result = RubyHash.newHash(runtime);

            IRubyObject createId = RuntimeInfo.forRuntime(runtime)
                    .jsonModule.get().callMethod(context, "create_id");
            result.op_aset(context, createId, self.getMetaClass().to_s());

            ByteList bl = self.getByteList();
            byte[] uBytes = bl.unsafeBytes();
            RubyArray array = runtime.newArray(bl.length());
            for (int i = bl.begin(), t = bl.begin() + bl.length(); i < t; i++) {
                array.store(i, runtime.newFixnum(uBytes[i] & 0xff));
            }

            result.op_aset(context, runtime.newString("raw"), array);
            return result;
        }

        @JRubyMethod(required=1, module=true)
        public static IRubyObject included(ThreadContext context,
                IRubyObject vSelf, IRubyObject module) {
            RuntimeInfo info = RuntimeInfo.forRuntime(context.getRuntime());
            return module.callMethod(context, "extend", info.stringExtendModule.get());
        }
    }

    public static class StringExtend {
        /**
         * <code>{@link RubyString String}#json_create(o)</code>
         *
         * <p>Raw Strings are JSON Objects (the raw bytes are stored in an
         * array for the key "raw"). The Ruby String can be created by this
         * module method.
         */
        @JRubyMethod(required=1)
        public static IRubyObject json_create(ThreadContext context,
                IRubyObject vSelf, IRubyObject vHash) {
            Ruby runtime = context.getRuntime();
            RubyHash o = vHash.convertToHash();
            IRubyObject rawData = o.fastARef(runtime.newString("raw"));
            if (rawData == null) {
                throw runtime.newArgumentError("\"raw\" value not defined "
                                               + "for encoded String");
            }
            RubyArray ary = Utils.ensureArray(rawData);
            byte[] bytes = new byte[ary.getLength()];
            for (int i = 0, t = ary.getLength(); i < t; i++) {
                IRubyObject element = ary.eltInternal(i);
                if (element instanceof RubyFixnum) {
                    bytes[i] = (byte)RubyNumeric.fix2long(element);
                } else {
                    throw runtime.newTypeError(element, runtime.getFixnum());
                }
            }
            return runtime.newString(new ByteList(bytes, false));
        }
    }

    public static class RbTrue {
        @JRubyMethod(rest=true)
        public static IRubyObject to_json(ThreadContext context,
                IRubyObject vSelf, IRubyObject[] args) {
            return Generator.generateJson(context, (RubyBoolean)vSelf,
                    Generator.TRUE_HANDLER, args);
        }
    }

    public static class RbFalse {
        @JRubyMethod(rest=true)
        public static IRubyObject to_json(ThreadContext context,
                IRubyObject vSelf, IRubyObject[] args) {
            return Generator.generateJson(context, (RubyBoolean)vSelf,
                    Generator.FALSE_HANDLER, args);
        }
    }

    public static class RbNil {
        @JRubyMethod(rest=true)
        public static IRubyObject to_json(ThreadContext context,
                IRubyObject vSelf, IRubyObject[] args) {
            return Generator.generateJson(context, vSelf,
                    Generator.NIL_HANDLER, args);
        }
    }

    public static class RbObject {
        @JRubyMethod(rest=true)
        public static IRubyObject to_json(ThreadContext context,
                IRubyObject self, IRubyObject[] args) {
            return RbString.to_json(context, self.asString(), args);
        }
    }
}
