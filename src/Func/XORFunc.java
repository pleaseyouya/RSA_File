package Func;

import java.io.IOException;
import java.util.Arrays;

import Util.SerialUtil;

public class XORFunc {
	/**
	 * 用异或的方式对byte数组进行加解密
	 * 
	 * @param raw
	 *            待加密/解密的byte数组
	 * @param key
	 *            用于异或操作的key
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
	 * 对指定的文件，进行加密操作并输出
	 * 
	 * @param inputFile
	 *            待加密的文件
	 * @param key
	 *            加密用的key，即空间所对应的密码
	 * @param outputPath
	 *            加密后的文件路径
	 * @throws IOException
	 */
	public static void encryptFile(String inputFile, int key, String outputPath) {

		try {
			byte[] fileBytes;
			fileBytes = SerialUtil.fileToBytes(inputFile);

			// 把源地址路径补上
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
			System.err.println("文件读取错误，请检查输入文件是否存在");
			e.printStackTrace();
		}
	}
	/**
	 * 对指定的文件进行解密，输出解密后的文件，返回该文件原始的路径
	 * @param inputFile
	 * 				指定的待解密文件
	 * @param key
	 * 				解密用到的key
	 * @param outputPath
	 * 				解密后文件的输出路径
	 * @return
	 * 				该文件加密前的地址
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

			// 尝试从原始路径中获取文件后缀名补充到输出路径上
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
			System.err.println("文件读取错误，请检查输入文件是否存在");
			e.printStackTrace();
		}
		return null;
	}
}
