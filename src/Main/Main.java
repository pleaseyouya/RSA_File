package Main;

import java.io.IOException;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CountDownLatch;

import org.json.JSONObject;

import com.sun.jndi.url.corbaname.corbanameURLContextFactory;
import com.sun.nio.sctp.SctpStandardSocketOptions.InitMaxStreams;

import Func.Function;
import Func.XORFunc;
import Func.AESFunc;
import Util.RSAUtil;
import Util.SerialUtil;


public class Main {

	
	/**
	 *
	 * @param args
	 * @throws Exception
	 */
	public static void main(String[] args) throws Exception {
		String inputFile = "D:/DTLDownLoads/aaa.jpg";
		String encryptFile = "D:/DTLDownLoads/encrypt.dat";
		String decryptFile = "D:/DTLDownLoads/decrypt";
		//AES加密算法
		
		String key = "1234";
		//加密
		AESFunc.encryptFile(inputFile, key, encryptFile);
		
		//解密   
		String originalPath = AESFunc.decryptFile2File(encryptFile, key, decryptFile);
		System.out.println(originalPath);

	}
	
}
