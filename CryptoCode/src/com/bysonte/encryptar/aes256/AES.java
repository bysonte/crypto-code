package com.bysonte.encryptar.aes256;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
/**
Aes encryption
*/
public class AES{
    
    private static SecretKeySpec secretKey ;
    private static byte[] key ;
    
    private static String decryptedString;
    private static String encryptedString;
    
    public static String toHex(String arg) {
        return String.format("%040x", new BigInteger(1, arg.getBytes(/*YOUR_CHARSET?*/)));
    }
    
    public static void main(String args[]){
    	final String strToEncrypt = "1122334455667788";
    	final String strPssword = "F4C86404-3662-4760-8A6A-38CF3996";
    	
    	System.out.println("Seed in hex: " + AES.toHex(strPssword));
    	System.out.println("TextToEncrypt in hex: " + AES.toHex(strToEncrypt));
    	AES.setKey(strPssword);
	   
	    AES.encrypt(strToEncrypt.trim());
	    
	    System.out.println("String to Encrypt: " + strToEncrypt); 
	    String strEncrypted = AES.getEncryptedString();
	    System.out.println("Encrypted: " + strEncrypted);
	    System.out.println("TextEncrypted in hex: " + AES.toHex(strEncrypted));
	    
	    final String strToDecrypt =  AES.getEncryptedString();
	    AES.decrypt(strToDecrypt.trim());
	    
	    System.out.println("String To Decrypt : " + strToDecrypt);
	    System.out.println("Decrypted : " + AES.getDecryptedString());
    }
    
    public static void setKey(String myKey){
        try {
        	MessageDigest sha = null;
            key = myKey.getBytes("UTF-8");
            System.out.println("###################");
            System.out.println("PublicKey " + myKey);
            System.out.println("PublicKey length " + key.length);
            
            sha = MessageDigest.getInstance("SHA-256");
            key = sha.digest(key);
            //key = Arrays.copyOf(key, 32); // use only first 128 bit
            System.out.println("PublicKey length digest " + key.length);
            System.out.println("###################");
            //System.out.println(new String(key,"UTF-8"));
            secretKey = new SecretKeySpec(key, "AES");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        
              
    
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
    public static String encrypt(String strToEncrypt){
        try{
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
         
            setEncryptedString(Base64.encodeBase64String(cipher.doFinal(strToEncrypt.getBytes("UTF-8"))));
        }catch (Exception e){
            System.out.println("Error while encrypting: " + e.toString());
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
}
