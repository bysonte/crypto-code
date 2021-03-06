package com.bysonte.encryptar.aes256;

import java.security.AlgorithmParameters;

import java.security.SecureRandom;

import javax.crypto.BadPaddingException;

import javax.crypto.Cipher;

import javax.crypto.IllegalBlockSizeException;

import javax.crypto.SecretKey;

import javax.crypto.SecretKeyFactory;

import javax.crypto.spec.IvParameterSpec;

import javax.crypto.spec.PBEKeySpec;

import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

 

public class AESDemo {
	 public static void main(String[] args) throws Exception {
		 //key: F4C86404-3662-4760-8A6A-38CF3996C1950.130348
		 
	        // TODO Auto-generated method stub
	        AESDemo d = new AESDemo();
	        String textToEncrypt = "4544332266778899";
	        System.out.println("String to encrypt: " + textToEncrypt);
	        
	        String encryptedText = d.encrypt(textToEncrypt);
	        System.out.println("Encrypted string:" + encryptedText);           
	        String decryptedText = d.decrypt(encryptedText);
	        System.out.println("Decrypted string:" + decryptedText);         
	    }
 

    private static final String password = "F4C86404-3662-4760-8A6A-38CF3996C1950.130348";
    private static byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
    private static int pswdIterations = 65536  ;
    private static int keySize = 256;
    private byte[] ivBytes;

    
    public String encrypt(String plainText) throws Exception {   
        //get salt
        //salt = generateSalt();      
        //byte[] saltBytes = salt.getBytes("UTF-8");
        // Derive the key
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), saltBytes, pswdIterations, keySize);
 
        SecretKey secretKey = factory.generateSecret(spec);
        SecretKeySpec secret = new SecretKeySpec(secretKey.getEncoded(), "AES");
 
        //encrypt the message
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secret);
        AlgorithmParameters params = cipher.getParameters();
        ivBytes = params.getParameterSpec(IvParameterSpec.class).getIV();
        byte[] encryptedTextBytes = cipher.doFinal(plainText.getBytes("UTF-8"));
        return new Base64().encodeAsString(encryptedTextBytes);
    }
 
    @SuppressWarnings("static-access")
    public String decrypt(String encryptedText) throws Exception {
 
        //byte[] saltBytes = salt.getBytes("UTF-8");
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
 
    public String generateSalt() {
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[20];
        random.nextBytes(bytes);
        String s = new String(bytes);
        return s;
    }
}
