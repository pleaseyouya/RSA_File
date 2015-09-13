package Util;


import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.math.BigInteger;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileChannel.MapMode;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.crypto.Cipher;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class RSAUtil {
	
	public static final String PADDING = "RSA/NONE/PKCS1Padding";
	//public static final String PADDING = "RSA/None/NoPadding";

	/**
	 * ������Կ��
	 * 
	 * @return
	 * @throws Exception
	 */
	public static KeyPair generateKeyPair() throws Exception {
		try {
			KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA", new BouncyCastleProvider());
			//final int KEY_SIZE = 1024;// ûʲô��˵���ˣ����ֵ��ϵ������ܵĴ�С�����Ը��ģ����ǲ�Ҫ̫�󣬷���Ч�ʻ��
			final int KEY_SIZE =88 + 8 * 15;
			keyPairGen.initialize(KEY_SIZE);
			KeyPair keyPair = keyPairGen.genKeyPair();
			return keyPair;
		} catch (Exception e) {
			throw new Exception(e.getMessage());
		}
	}

	/**
	 * ���ɹ�Կ
	 * 
	 * @param modulus
	 * @param publicExponent
	 * @return
	 * @throws Exception
	 */
	public static RSAPublicKey generateRSAPublicKey(byte[] modulus, byte[] publicExponent) throws Exception {
		KeyFactory keyFac = null;
		try {
			keyFac = KeyFactory.getInstance("RSA", new org.bouncycastle.jce.provider.BouncyCastleProvider());
		} catch (NoSuchAlgorithmException ex) {
			throw new Exception(ex.getMessage());
		}

		RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(new BigInteger(modulus), new BigInteger(publicExponent));
		try {
			return (RSAPublicKey) keyFac.generatePublic(pubKeySpec);
		} catch (InvalidKeySpecException ex) {
			throw new Exception(ex.getMessage());
		}
	}

	/**
	 * ����˽Կ
	 * 
	 * @param modulus
	 * @param privateExponent
	 * @return
	 * @throws Exception
	 */
	public static RSAPrivateKey generateRSAPrivateKey(byte[] modulus, byte[] privateExponent) throws Exception {
		KeyFactory keyFac = null;
		try {
			keyFac = KeyFactory.getInstance("RSA", new BouncyCastleProvider());
		} catch (NoSuchAlgorithmException ex) {
			throw new Exception(ex.getMessage());
		}

		RSAPrivateKeySpec priKeySpec = new RSAPrivateKeySpec(new BigInteger(modulus), new BigInteger(privateExponent));
		try {
			return (RSAPrivateKey) keyFac.generatePrivate(priKeySpec);
		} catch (InvalidKeySpecException ex) {
			throw new Exception(ex.getMessage());
		}
	}

	/**
	 * ����
	 * 
	 * @param priKey
	 *            ���ܵ���Կ
	 * @param data
	 *            �����ܵ���������
	 * @return ���ܺ������
	 * @throws EncryptException
	 */
	public static byte[] encrypt(RSAPublicKey pubKey, byte[] data) throws Exception {
		try {
			Cipher cipher = Cipher.getInstance(PADDING,	new BouncyCastleProvider());
			
			cipher.init(Cipher.ENCRYPT_MODE, pubKey);
			int blockSize = cipher.getBlockSize();// ��ü��ܿ��С���磺����ǰ����Ϊ128��byte��
			System.err.println("blockSize " + blockSize);
			// ��key_size=1024 ���ܿ��СΪ127
			// byte
			// ,���ܺ�Ϊ128��byte;��˹���2�����ܿ�
			// ����һ��127 byte�ڶ���Ϊ1��byte
			int outputSize = cipher.getOutputSize(data.length);// ��ü��ܿ���ܺ���С
			int leavedSize = data.length % blockSize;
			int blocksSize = leavedSize != 0 ? data.length / blockSize + 1 : data.length / blockSize;
			byte[] raw = new byte[outputSize * blocksSize];
			int i = 0;
			while (data.length - i * blockSize > 0) {
				if (data.length - i * blockSize > blockSize)
					cipher.doFinal(data, i * blockSize, blockSize, raw, i * outputSize);
				else
					cipher.doFinal(data, i * blockSize, data.length - i * blockSize, raw, i * outputSize);
				// ������doUpdate���������ã��鿴Դ�������ÿ��doUpdate��û��ʲôʵ�ʶ������˰�byte[]
				// �ŵ�ByteArrayOutputStream�У������doFinal��ʱ��Ž����е�byte[]���м��ܣ�
				// ���ǵ��˴�ʱ���ܿ��С�ܿ����Ѿ�������OutputSize����ֻ����dofinal������

				i++;
			}
			return raw;
		} catch (Exception e) {
			throw new Exception(e.getMessage());
		}
	}

	/**
	 * ����
	 *
	 * @param recoveryPubKey
	 *            ���ܵ���Կ
	 * @param raw
	 *            �Ѿ����ܵ�����
	 * @return ���ܺ������
	 * @throws EncryptException
	 */
	public static byte[] decrypt(RSAPrivateKey recoveryPriKey, byte[] raw) throws Exception {
		try {
			Cipher cipher = Cipher.getInstance(PADDING,	new BouncyCastleProvider());
			cipher.init(cipher.DECRYPT_MODE, recoveryPriKey);
			int blockSize = cipher.getBlockSize();
			ByteArrayOutputStream bout = new ByteArrayOutputStream(64);
			int j = 0;

			while (raw.length - j * blockSize > 0) {
				// bout.write(cipher.doFinal(raw, j * blockSize, blockSize));
				// j++;
				if (raw.length - j * blockSize > blockSize)
					bout.write(cipher.doFinal(raw, j * blockSize, blockSize));
				else
					bout.write(cipher.doFinal(raw, j * blockSize, raw.length - j * blockSize));
				j++;
			}
			return bout.toByteArray();
		} catch (Exception e) {
			throw new Exception(e.getMessage());
		}
	}

	  
	
	

}