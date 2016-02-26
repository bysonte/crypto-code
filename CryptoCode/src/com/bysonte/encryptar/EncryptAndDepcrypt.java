package com.bysonte.encryptar;


import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptAndDepcrypt {

	static String stringInput = "Some text here!";
	
	
	byte[] input;
	byte[] keyBytes = "12345678".getBytes();
	byte[] ivBytes = "input123".getBytes();
	
	SecretKeySpec key = new SecretKeySpec(keyBytes, "DES");
	IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
	
	Cipher cipher;
	byte[] cipherText;
	byte[] plainText;
	int ctLength;
	int ptLength;
	
	
	public void encriptar(){
		try{
		//Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			input = stringInput.getBytes();
			
			cipher = Cipher.getInstance("DES/CTR/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
			
			cipherText = new byte[cipher.getOutputSize(input.length)];
			
			ctLength = cipher.update(input, 0, input.length, cipherText, 0);
			ctLength += cipher.doFinal(cipherText, ctLength);
			
			System.out.println("Texto encriptado: >> " + cipherText.toString());
		}catch(Exception e){
			e.printStackTrace();
		}
	}
	
	public void desencriptar(){
		try{
			cipher = Cipher.getInstance("DES/CTR/NoPadding");
			cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
			
			plainText = new byte[cipher.getOutputSize(ctLength)];
			
			ptLength = cipher.update(cipherText, 0, ctLength, plainText, 0);
			
			ptLength += cipher.doFinal(plainText, ptLength);
			
			System.out.println("Texto desencriptado: >> " + plainText.toString());
		}catch(Exception e){
			e.printStackTrace();
		}
	}
	public static void main(String[] args) {
		System.out.println("Texto original: >> " + stringInput);
		EncryptAndDepcrypt run = new EncryptAndDepcrypt();
		
		run.encriptar();
		run.desencriptar();
	}

}
