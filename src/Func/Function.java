package Func;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;

import javax.sound.midi.SysexMessage;

import org.json.JSONObject;

import Util.*;

public class Function {
	/**
	 * ������Կ�Բ������ַ�����ʽ����Կ�ԣ�pub��ǰ��pri�ں�
	 * @return
	 * 		����ArrayList��ʽ,pubKey��ǰ��priKey�ں�
	 */
	public static ArrayList<String> generateKeyStr(){
		KeyPair keyPair;
		try {
			keyPair = RSAUtil.generateKeyPair();
			RSAPublicKey pubKey = (RSAPublicKey) keyPair.getPublic();
			RSAPrivateKey priKey = (RSAPrivateKey) keyPair.getPrivate();
			
			String pubKeyStr = SerialUtil.getKeyString(pubKey);
			String priKeyStr = SerialUtil.getKeyString(priKey);
			ArrayList<String> keyStrPair = new ArrayList<String>();
			keyStrPair.add(pubKeyStr);
			keyStrPair.add(priKeyStr);
			return keyStrPair;
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			System.err.println("������Կ��ʧ�ܣ�");
		}
		return null;
		
	}
	/**
	 * ��Json������м��ܲ�������ܺ���ļ�
	 * @param source
	 * 			�����ܵ��ַ���
	 * @param pubKeyStr
	 *			�����õĹ�Կ���ַ�����ʽ
	 * @param outputPath
	 * 			���ܺ�Ľ�����·��
	 * @throws Exception
	 */
	public static void encryptJson(JSONObject source, String pubKeyStr, String outputPath ) 
			throws Exception{
		RSAPublicKey pubKey = (RSAPublicKey)SerialUtil.getPublicKey(pubKeyStr);
		byte[] encryptResult = RSAUtil.encrypt(pubKey, source.toString().getBytes());
		SerialUtil.bytesToFile(encryptResult, outputPath);
	}
	/**
	 * ��ָ���ļ����м��ܲ�������ܺ���ļ�
	 * @param inputFile
	 * 			�����ܵ��ļ�·��
	 * @param pubKeyStr
	 *			�����õĹ�Կ���ַ�����ʽ
	 * @param outputPath
	 * 			���ܺ�Ľ�����·��
	 * @throws Exception
	 */
	public static void encryptFile(String inputFile, String pubKeyStr, String outputPath ) 
			throws Exception{
		RSAPublicKey pubKey = (RSAPublicKey)SerialUtil.getPublicKey(pubKeyStr);
		byte[] fileBytes = SerialUtil.fileToBytes(inputFile);
		
		//��Դ��ַ·������
		byte[] pathBytes = inputFile.getBytes();
		int len = pathBytes.length;
		byte[] lenBytes= SerialUtil.intToBytes(len);
		int totalLen = lenBytes.length + pathBytes.length + fileBytes.length;
		byte[] raw = Arrays.copyOf(lenBytes, totalLen);
		//lenBytes.length == 4
		System.arraycopy(pathBytes, 0, raw, 4, pathBytes.length);
		System.arraycopy(fileBytes, 0, raw, 4 + pathBytes.length, fileBytes.length);

		byte[] encryptResult = RSAUtil.encrypt(pubKey, raw);
		
		SerialUtil.bytesToFile(encryptResult, outputPath);

	}

	/**
	 * ��ȡ���ܺ����Կ�ļ������ܣ�����json����
	 * @param inputFile
	 * 				���ܺ����Կ�ļ�
	 * @param priKeyStr
	 * 				�����õ�˽Կ���ַ�����ʽ
	 * @return
	 */
	public static JSONObject decryptFile2Json(String inputFile, String priKeyStr){
		try {				
			RSAPrivateKey priKey = (RSAPrivateKey)SerialUtil.getPrivateKey(priKeyStr);
			byte[] priModBytes = priKey.getModulus().toByteArray();
			byte[] priPriExpBytes = priKey.getPrivateExponent().toByteArray();
			RSAPrivateKey recoveryPriKey = RSAUtil.generateRSAPrivateKey(priModBytes, priPriExpBytes);
			
			byte[] raw = SerialUtil.fileToBytes(inputFile);	
			byte[] result = RSAUtil.decrypt(recoveryPriKey, raw);
			JSONObject jsonObject = new JSONObject(new String(result));
			return jsonObject;
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	/**
	 * �����ܺ���ļ����ܲ������ָ��·��
	 * @param inputFile
	 * 				���ܺ���ļ�
	 * @param priKeyStr
	 * 				���ڽ��ܵ�˽Կ���ַ�����ʽ
	 * @param outputPath
	 * 				���ܺ��ļ������·��
	 */
	public static String decryptFile2File(String inputFile, String priKeyStr, String outputPath){
		try {				
			RSAPrivateKey priKey = (RSAPrivateKey)SerialUtil.getPrivateKey(priKeyStr);
			byte[] priModBytes = priKey.getModulus().toByteArray();
			byte[] priPriExpBytes = priKey.getPrivateExponent().toByteArray();
			RSAPrivateKey recoveryPriKey = RSAUtil.generateRSAPrivateKey(priModBytes, priPriExpBytes);
			
			byte[] raw = SerialUtil.fileToBytes(inputFile);				
			byte[] result = RSAUtil.decrypt(recoveryPriKey, raw);
			
			byte[] lenBytes = Arrays.copyOf(result, 4);
			int pathLen = SerialUtil.bytesToInt(lenBytes, 0);
			byte[] pathBytes = new byte[pathLen];
			System.arraycopy(result, 4, pathBytes, 0, pathLen);
			String path = new String(pathBytes);
			String [] parts = path.split("\\.");
			
			//���Դ�ԭʼ·���л�ȡ�ļ���׺�����䵽���·����
			if(parts.length >=2){
				String postFix = "." + parts[parts.length-1];
				if(!outputPath.endsWith(postFix)){
					outputPath += postFix;
				}
			}
							
			int fileLen = result.length - 4 - pathLen;
			byte[] fileBytes = new byte[fileLen];
			System.arraycopy(result, 4+pathLen, fileBytes, 0, fileLen);

			SerialUtil.bytesToFile(fileBytes, outputPath);
			
			return path;
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
}
