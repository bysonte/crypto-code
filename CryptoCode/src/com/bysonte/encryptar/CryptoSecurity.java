package com.bysonte.encryptar;

//Java code - Cipher mode CBC version.
//CBC version need Initialization vector IV.
//Reference from http://stackoverflow.com/questions/6669181/why-does-my-aes-encryption-throws-an-invalidkeyexception/6669812#6669812

import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base64;

public class CryptoSecurity {

 //public static String key = "#C4e4.d53.0fp4e.f3.4p53eq3.q3.z1.z1.z1.z11";
 //public static String key = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
 //public static String key = "############################################";
 public static String key = "C4e4.d53.0fp4e.f3.4p53eq3.q3.z1.z1.z1.z1z1";
 public static byte[] key_Array = Base64.decodeBase64(key);

 public static String encrypt(String strToEncrypt)
 {       
     try
     {   
    	 System.out.println("Key Length: "+key.length());
    	 System.out.println("Byte length: " + key_Array.length);
         //Cipher _Cipher = Cipher.getInstance("AES");
         //Cipher _Cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
         Cipher _Cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");        

         // Initialization vector.   
         // It could be any value or generated using a random number generator.
         byte[] iv = { 1, 2, 3, 4, 5, 6, 6, 5, 4, 3, 2, 1, 7, 7, 7, 7 };
         IvParameterSpec ivspec = new IvParameterSpec(iv);

         Key SecretKey = new SecretKeySpec(key_Array, "AES");    
         _Cipher.init(Cipher.ENCRYPT_MODE, SecretKey, ivspec);       

         return Base64.encodeBase64String(_Cipher.doFinal(strToEncrypt.getBytes()));     
     }
     catch (Exception e)
     {
         System.out.println("[Exception]:"+e.getMessage());
     }
     return "";
 }

 public static String decrypt(String EncryptedMessage)
 {
     try
     {
         //Cipher _Cipher = Cipher.getInstance("AES");
         //Cipher _Cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
         Cipher _Cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");            

         // Initialization vector.   
         // It could be any value or generated using a random number generator.
         byte[] iv = { 1, 2, 3, 4, 5, 6, 6, 5, 4, 3, 2, 1, 7, 7, 7, 7 };
         IvParameterSpec ivspec = new IvParameterSpec(iv);

         Key SecretKey = new SecretKeySpec(key_Array, "AES");
         _Cipher.init(Cipher.DECRYPT_MODE, SecretKey, ivspec);           

         byte DecodedMessage[] = Base64.decodeBase64(EncryptedMessage);
         return new String(_Cipher.doFinal(DecodedMessage));

     }
     catch (Exception e)
     {
         System.out.println("[Exception]:"+e.getMessage());          

     }
     return "";
 }

 public static void main(String[] args) {
     //StringBuilder sb = new StringBuilder();
     //sb.append("xml file string ...");

	 String messageToEncrypt = "4444555566667777";
     
     String outputOfEncrypt = encrypt(messageToEncrypt);        
     System.out.println("[CryptoSecurity.outputOfEncrypt]: " + outputOfEncrypt);

     String outputOfDecrypt = decrypt(outputOfEncrypt);        
     //String outputOfDecrypt = decrypt(sb.toString());        
     System.out.println("[CryptoSecurity.outputOfDecrypt]: " + outputOfDecrypt);
 }

}