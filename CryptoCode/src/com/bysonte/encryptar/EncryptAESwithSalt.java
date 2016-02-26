package com.bysonte.encryptar;

import java.security.AlgorithmParameters;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

import sun.misc.BASE64Encoder;

public class EncryptAESwithSalt {
	public static void main(String[] args) throws Exception { 
	String message="4444555566667777";
	System.out.println("Texto a encryptar: " + message);
	
	String llaveMagica = "#C4e4.d53.0fp4e.f3.4p53eq3.q3.z1";
	
	char[] password = llaveMagica.toCharArray();
	byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
	/* Derive the key, given password and salt. */
	SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
	KeySpec spec = new PBEKeySpec(password, saltBytes, 1000, 256);
	SecretKey tmp = factory.generateSecret(spec);
	SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");
	
	/* Encrypt the message. */
	Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
	cipher.init(Cipher.ENCRYPT_MODE, secret);
	AlgorithmParameters params = cipher.getParameters();
	byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
	byte[] ciphertext = cipher.doFinal(message.getBytes("UTF-8"));
	System.out.println("encrypted string [byte format]: " + ciphertext);
	
	/* byte to Base64 */
	Base64 enc = new Base64();
	enc.encode(ciphertext);
    String s = new BASE64Encoder().encode(ciphertext);
	System.out.println("encrypted string base64: " + s);
	
	Base64 enc1 = new Base64();
	enc1.encode(iv);
    String s1 = new BASE64Encoder().encode(iv);
	System.out.println("Initialization vector: " + s1);
	
	
	/* Decrypt the message, given derived key and initialization vector. */
	Cipher cipher1 = Cipher.getInstance("AES/CBC/PKCS7Padding");
	cipher1.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));
	String plaintext = new String(cipher1.doFinal(ciphertext), "UTF-8");
	System.out.println("decrypted string: " + plaintext);
	
	}
}
