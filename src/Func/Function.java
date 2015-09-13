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
	 * 生成密钥对并返回字符串格式的密钥对，pub在前，pri在后
	 * @return
	 * 		返回ArrayList格式,pubKey在前，priKey在后
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
			System.err.println("生成密钥对失败！");
		}
		return null;
		
	}
	/**
	 * 对Json对象进行加密并输出加密后的文件
	 * @param source
	 * 			待加密的字符串
	 * @param pubKeyStr
	 *			加密用的公钥，字符串格式
	 * @param outputPath
	 * 			加密后的结果输出路径
	 * @throws Exception
	 */
	public static void encryptJson(JSONObject source, String pubKeyStr, String outputPath ) 
			throws Exception{
		RSAPublicKey pubKey = (RSAPublicKey)SerialUtil.getPublicKey(pubKeyStr);
		byte[] encryptResult = RSAUtil.encrypt(pubKey, source.toString().getBytes());
		SerialUtil.bytesToFile(encryptResult, outputPath);
	}
	/**
	 * 对指定文件进行加密并输出加密后的文件
	 * @param inputFile
	 * 			待加密的文件路径
	 * @param pubKeyStr
	 *			加密用的公钥，字符串格式
	 * @param outputPath
	 * 			加密后的结果输出路径
	 * @throws Exception
	 */
	public static void encryptFile(String inputFile, String pubKeyStr, String outputPath ) 
			throws Exception{
		RSAPublicKey pubKey = (RSAPublicKey)SerialUtil.getPublicKey(pubKeyStr);
		byte[] fileBytes = SerialUtil.fileToBytes(inputFile);
		
		//把源地址路径补上
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
	 * 读取加密后的密钥文件并解密，返回json对象
	 * @param inputFile
	 * 				加密后的密钥文件
	 * @param priKeyStr
	 * 				解密用的私钥，字符串格式
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
	 * 将加密后的文件解密并输出到指定路径
	 * @param inputFile
	 * 				加密后的文件
	 * @param priKeyStr
	 * 				用于解密的私钥，字符串格式
	 * @param outputPath
	 * 				解密后文件的输出路径
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
			
			//尝试从原始路径中获取文件后缀名补充到输出路径上
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
