package com.bysonte.encryptar;

import java.security.AlgorithmParameters;
import java.security.MessageDigest;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class AES256 {
	private static String password = "F4C86404-3662-4760-8A6A-38CF3996C1950.130348";
	private static String salt;
	private static int pswdIterations = 65536;
	private static int keySize = 256;
	private byte[] ivBytes;
	
	public String encrypt2(String seed, String plainText) throws Exception {
		byte[] key = seed.getBytes("UTF-8"); 
		byte[] input = plainText.getBytes("UTF-8"); 
		
    	MessageDigest sha = MessageDigest.getInstance("SHA-256");
    	key = sha.digest(key);
    	SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
		
		Cipher cipher2 = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher2.init(Cipher.ENCRYPT_MODE, keySpec);
		
		return new Base64().encodeAsString(cipher2.doFinal(input));
	}
	public String encrypt(String seed, String plainText) throws Exception {
		password = seed;
		//salt = seed;
		byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
		System.out.println(saltBytes.toString());
		// Derive the key
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		KeySpec spec = new PBEKeySpec(password.toCharArray(), saltBytes, pswdIterations, keySize);
		
		//PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), saltBytes, pswdIterations, keySize);
		SecretKey secretKey = factory.generateSecret(spec);
		SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), "AES");
		
		// encrypt the message
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, secret);
		
		AlgorithmParameters params = cipher.getParameters();
		ivBytes = params.getParameterSpec(IvParameterSpec.class).getIV();
		
		byte[] encryptedTextBytes = cipher.doFinal(plainText.getBytes("UTF-8"));
		return new Base64().encodeAsString(encryptedTextBytes);
	}
	
	
	
	@SuppressWarnings("static-access")
		public String decrypt(String encryptedText) throws Exception {
		byte[] saltBytes = salt.getBytes("UTF-8");
		byte[] encryptedTextBytes = new Base64().decodeBase64(encryptedText);
		
		// Derive the key
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), saltBytes, pswdIterations, keySize);
		SecretKey secretKey = factory.generateSecret(spec);
		SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), "AES");
		
		// Decrypt the message
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(ivBytes));
		
		byte[] decryptedTextBytes = null;
		
		try {
			decryptedTextBytes = cipher.doFinal(encryptedTextBytes);
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
		return new String(decryptedTextBytes);
	}
	public static void main(String[] args) throws Exception {

        AES256 d = new AES256();
             
        System.out.println("Encrypted string:" + d.encrypt("F4C86404-3662-4760-8A6A-38CF3996C1950.130348", "1111222233334444")); 
        
        System.out.println("New version: " + d.encrypt2("F4C86404-3662-4760-8A6A-38CF3996C1950.130348", "1111222233334444"));
        //String encryptedText = d.encrypt("F4C86404-3662-4760-8A6A-38CF3996C1950.130348", "1111222233334444");
        //System.out.println("Decrypted string:" + d.decrypt(encryptedText));         

    }
}
