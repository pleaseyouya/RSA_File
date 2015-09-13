package Func;

import java.io.IOException;
import java.util.Arrays;

import Util.SerialUtil;

public class XORFunc {
	/**
	 * �����ķ�ʽ��byte������мӽ���
	 * 
	 * @param raw
	 *            ������/���ܵ�byte����
	 * @param key
	 *            ������������key
	 * @return
	 */
	public static byte[] myEncrypt(byte[] raw, int key) {
		byte[] result = new byte[raw.length];
		byte[] keyByte = SerialUtil.intToBytes(key);
		int iter = 0;
		for (byte b : raw) {
			result[iter] = (byte) (b ^ keyByte[iter % 4]);
			iter++;
		}
		return result;
	}

	/**
	 * ��ָ�����ļ������м��ܲ��������
	 * 
	 * @param inputFile
	 *            �����ܵ��ļ�
	 * @param key
	 *            �����õ�key�����ռ�����Ӧ������
	 * @param outputPath
	 *            ���ܺ���ļ�·��
	 * @throws IOException
	 */
	public static void encryptFile(String inputFile, int key, String outputPath) {

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

			byte[] encryptResult = myEncrypt(raw, key);

			SerialUtil.bytesToFile(encryptResult, outputPath);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			System.err.println("�ļ���ȡ�������������ļ��Ƿ����");
			e.printStackTrace();
		}
	}
	/**
	 * ��ָ�����ļ����н��ܣ�������ܺ���ļ������ظ��ļ�ԭʼ��·��
	 * @param inputFile
	 * 				ָ���Ĵ������ļ�
	 * @param key
	 * 				�����õ���key
	 * @param outputPath
	 * 				���ܺ��ļ������·��
	 * @return
	 * 				���ļ�����ǰ�ĵ�ַ
	 */
	public static String decryptFile2File(String inputFile, int key, String outputPath) {
		try {
			byte[] raw = SerialUtil.fileToBytes(inputFile);

			byte[] result = myEncrypt(raw, key);

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
}
