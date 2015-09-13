package Func;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import Util.SerialUtil;

public class AESFunc {
	public static void encryptFile(String inputFile, String key, String outputPath){
		try {
			byte[] fileBytes;
			fileBytes = SerialUtil.fileToBytes(inputFile);

			// ��Դ��ַ·������
			byte[] pathBytes = inputFile.getBytes();
			int len = pathBytes.length;
			byte[] lenBytes = SerialUtil.intToBytes(len);
			int totalLen = lenBytes.length + pathBytes.length + fileBytes.length;
			byte[] raw = Arrays.copyOf(lenBytes, totalLen);
			// lenBytes.length == 4
			System.arraycopy(pathBytes, 0, raw, 4, pathBytes.length);
			System.arraycopy(fileBytes, 0, raw, 4 + pathBytes.length, fileBytes.length);

			byte[] encryptResult = encrypt(raw, key);

			SerialUtil.bytesToFile(encryptResult, outputPath);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			System.err.println("�ļ���ȡ�������������ļ��Ƿ����");
			e.printStackTrace();
		}
	}
	public static String decryptFile2File(String inputFile, String key, String outputPath){
		try {
			byte[] raw = SerialUtil.fileToBytes(inputFile);

			byte[] result = decrypt(raw, key);

			byte[] lenBytes = Arrays.copyOf(result, 4);
			int pathLen = SerialUtil.bytesToInt(lenBytes, 0);
			byte[] pathBytes = new byte[pathLen];
			System.arraycopy(result, 4, pathBytes, 0, pathLen);
			String path = new String(pathBytes);
			String[] parts = path.split("\\.");

			// ���Դ�ԭʼ·���л�ȡ�ļ���׺�����䵽���·����
			if (parts.length >= 2) {
				String postFix = "." + parts[parts.length - 1];
				if (!outputPath.endsWith(postFix)) {
					outputPath += postFix;
				}
			}

			int fileLen = result.length - 4 - pathLen;
			byte[] fileBytes = new byte[fileLen];
			System.arraycopy(result, 4 + pathLen, fileBytes, 0, fileLen);

			SerialUtil.bytesToFile(fileBytes, outputPath);

			return path;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			System.err.println("�ļ���ȡ�������������ļ��Ƿ����");
			e.printStackTrace();
		}
		return null;
	}
	
	/**
	 * ���ܷ���
	 * 
	 * @param content
	 *            ��Ҫ���ܵ�����
	 * @param password
	 *            ��������
	 * @return
	 */
	public static byte[] encrypt(byte[] content, String password) {
		try {
			KeyGenerator kgen = KeyGenerator.getInstance("AES");
			kgen.init(128, new SecureRandom(password.getBytes()));
			SecretKey secretKey = kgen.generateKey();
			byte[] enCodeFormat = secretKey.getEncoded();
			SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");
			Cipher cipher = Cipher.getInstance("AES");// ����������
			
			//byte[] byteContent = content.getBytes("utf-8");
			cipher.init(Cipher.ENCRYPT_MODE, key);// ��ʼ��
			byte[] result = cipher.doFinal(content);
			return result; // ����
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * ���ܷ���
	 * 
	 * @param content
	 *            ����������
	 * @param password
	 *            ������Կ
	 * @return
	 */
	public static byte[] decrypt(byte[] content, String password) {
		try {
			KeyGenerator kgen = KeyGenerator.getInstance("AES");
			kgen.init(128, new SecureRandom(password.getBytes()));
			SecretKey secretKey = kgen.generateKey();
			byte[] enCodeFormat = secretKey.getEncoded();
			SecretKeySpec key = new SecretKeySpec(enCodeFormat, "AES");
			Cipher cipher = Cipher.getInstance("AES");// ����������
			cipher.init(Cipher.DECRYPT_MODE, key);// ��ʼ��
			byte[] result = cipher.doFinal(content);
			return result; // ����
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		return null;
	}
	

}
