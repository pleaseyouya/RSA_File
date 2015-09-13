package Util;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileChannel.MapMode;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import org.json.JSONException;
import org.json.JSONObject;

public class SerialUtil {
	private static String RSA = "RSA";
	
	/** 
     * Mapped File way MappedByteBuffer ���ļ���ȡ��byte���� 
     *  
     * @param filename 
     * @return 
     * @throws IOException 
     */  
    public static byte[] fileToBytes(String filename) throws IOException {  
  
        FileChannel fc = null;  
        try {  
            fc = new RandomAccessFile(filename, "r").getChannel();  
            MappedByteBuffer byteBuffer = fc.map(MapMode.READ_ONLY, 0,  
                    fc.size()).load();  
            //System.out.println(byteBuffer.isLoaded());  
            byte[] result = new byte[(int) fc.size()];  
            if (byteBuffer.remaining() > 0) {  
                // System.out.println("remain");  
                byteBuffer.get(result, 0, byteBuffer.remaining());  
            }  
            return result;  
        } catch (IOException e) {  
            e.printStackTrace();  
            throw e;  
        } finally {  
            try {  
                fc.close();  
            } catch (IOException e) {  
                e.printStackTrace();  
            }  
        }  
    }
    /**
     * �����ܺ�õ���byte����д��ָ��·�����ļ�
     * @param bytes
     * @param outPath
     */
    public static void bytesToFile(byte[] bytes, String outPath){
    	try {
    		File file = new File(outPath);
	    	OutputStream out = new FileOutputStream(file);			
			out.write(bytes);
			out.flush();
			out.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }
    
    /**
     * ��������Կ��map��Ϊjson��
     * @param myMap
     * @return
     * @throws JSONException
     */
    public static String convertToJson(Map<String, String> myMap) throws JSONException{
    	JSONObject jsonMap = new JSONObject(myMap);
    	/*Iterator iter = myMap.entrySet().iterator();
    	while(iter.hasNext()){
    		Map.Entry<String, String> entry = (Entry<String, String>) iter.next();
    		String key = entry.getKey();
    		String keyPair = entry.getValue();
    		jsonMap.put(key, keyPair);
    	}*/
    	return jsonMap.toString();
    }
    /**
     *  ��json����ԭ��map��key�����룬value���ı���ʽ����Կ
     * @param jsonString
     * @return
     */
    public static Map<String, String> convertToMap(String jsonString){
    	try {
			JSONObject ob = new JSONObject(jsonString);
			Iterator<String> iter = ob.keys();
			Map<String, String> code2key = new HashMap<String, String>();
			while(iter.hasNext()){
				String key = (String) iter.next();
				String value = (String)ob.get(key);
				code2key.put(key, value);
			}
			return code2key;
		} catch (JSONException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	return null;
    }
    /**
     * ���ַ����õ���Կ
     * @param key ��Կ�ַ���������base64���룩
     * @throws Exception
     */
    public static PublicKey getPublicKey(String key) throws Exception {
    	  X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64Utils.decode(key));

          KeyFactory keyFactory = KeyFactory.getInstance("RSA");
          PublicKey publicKey = keyFactory.generatePublic(keySpec);
          return publicKey;
    }
    /**
     * ���ַ����õ�˽Կ
     * @param key ��Կ�ַ���������base64���룩
     * @throws Exception
     */
    public static PrivateKey getPrivateKey(String key) throws Exception {
    	  PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64Utils.decode(key));
          
          KeyFactory keyFactory = KeyFactory.getInstance("RSA");
          PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
          return privateKey;
    }

    /**
     * ��keyת��Ϊ�ַ���������base64���룩
     * @return
     */
    public static String getKeyString(Key key) throws Exception {
          byte[] keyBytes = key.getEncoded();
          String s = Base64Utils.encode(keyBytes);
          return s;
    }
  
    /**
     * intתΪbyte���飬�̶�����Ϊ4
     * @param value
     * @return
     */
    public static byte[] intToBytes( int value )   
    {   
        byte[] src = new byte[4];  
        src[3] =  (byte) ((value>>24) & 0xFF);  
        src[2] =  (byte) ((value>>16) & 0xFF);  
        src[1] =  (byte) ((value>>8) & 0xFF);    
        src[0] =  (byte) (value & 0xFF);                  
        return src;   
    } 
    /**
     * byteתΪ���飬offsetĬ��Ϊ0
     * @param ary
     * @param offset
     * 			����������0
     * @return
     */
    public static int bytesToInt(byte[] ary, int offset) {  
	    int value;    
	    value = (int) ((ary[offset]&0xFF)   
	            | ((ary[offset+1]<<8) & 0xFF00)  
	            | ((ary[offset+2]<<16)& 0xFF0000)   
	            | ((ary[offset+3]<<24) & 0xFF000000));  
	    return value;  
	}  
}
