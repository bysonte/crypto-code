package com.bysonte.encryptar;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;



public class AES{
    private static SecretKeySpec secretKey ;
    private static byte[] key ;
    
	private static String decryptedString;
	private static String encryptedString;
 
    
    public static void setKey(String myKey){
    	MessageDigest sha = null;
		try {
			key = myKey.getBytes("UTF-8");
			System.out.println("PublicKey key.length: " + key.length);
			sha = MessageDigest.getInstance("SHA-256");
			key = sha.digest(key);
	    	//key = Arrays.copyOf(key, 32); // use only first 128 bit
	    	System.out.println("PublicKey key.length after sha digest: " + key.length);
		    secretKey = new SecretKeySpec(key, "AES");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
    }
    

	public static String encrypt(String strToEncrypt){
        try{
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
         
            setEncryptedString(Base64.encodeBase64String(cipher.doFinal(strToEncrypt.getBytes("UTF-8"))));
        }catch (Exception e){
            System.out.println("Error while encrypting: "+e.toString());
        }
        return null;

    }

    public static String decrypt(String strToDecrypt){
        try{
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            
            setDecryptedString(new String(cipher.doFinal(Base64.decodeBase64(strToDecrypt))));
        }catch (Exception e){
            System.out.println("Error while decrypting: "+e.toString());
        }
        return null;
    }


    public static void main(String args[]){
		//otYMC8kzV0DP6WJLl09G5Wr13dJMzLGns5tzxr97ZZw=
 
        final String strToEncrypt = "1111222233334444";
        System.out.println("String to Encrypt: " + strToEncrypt); 
        
        final String strPssword = "F4C86404-3662-4760-8A6A-38CF3996C1950.130348";
        System.out.println("PublicKey to Encrypt: " + strPssword); 
        
        AES.setKey(strPssword);
        AES.encrypt(strToEncrypt.trim());
        
        System.out.println("Encrypted: " + AES.getEncryptedString());
   
        final String strToDecrypt =  AES.getEncryptedString();
        AES.decrypt(strToDecrypt.trim());
       
        System.out.println("String To Decrypt : " + strToDecrypt);
        System.out.println("Decrypted : " + AES.getDecryptedString());
        
    }
     
    
    public static String getDecryptedString() {
		return decryptedString;
	}

	public static void setDecryptedString(String decryptedString) {
		AES.decryptedString = decryptedString;
	}

    public static String getEncryptedString() {
		return encryptedString;
	}

	public static void setEncryptedString(String encryptedString) {
		AES.encryptedString = encryptedString;
	}
}