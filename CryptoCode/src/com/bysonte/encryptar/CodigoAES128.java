package com.bysonte.encryptar;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

import com.bysonte.encryptar.interf.EncryptarInterface;

public class CodigoAES128 implements EncryptarInterface{

	@Override
	public String encryptar(String seed, String data) {
		String outputOfDecrypt = "";
		
		try {
			
			outputOfDecrypt = encrypt(data, seed);
			
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}

		return outputOfDecrypt;
	}
	
	private final String characterEncoding = "UTF-8";
	private final String cipherTransformation = "AES/CBC/PKCS5Padding";
	private final String aesEncryptionAlgorithm = "AES";

	public byte[] encrypt(byte[] plainText, byte[] key, byte[] initialVector) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance(cipherTransformation);
		SecretKeySpec secretKeySpec = new SecretKeySpec(key, aesEncryptionAlgorithm);
		IvParameterSpec ivParameterSpec = new IvParameterSpec(initialVector);
		cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
		plainText = cipher.doFinal(plainText);
		return plainText;
	}

	private byte[] getKeyBytes(String key) throws UnsupportedEncodingException {
		byte[] keyBytes = new byte[16];
		byte[] parameterKeyBytes = key.getBytes(characterEncoding);
		System.arraycopy(parameterKeyBytes, 0, keyBytes, 0, Math.min(parameterKeyBytes.length, keyBytes.length));
		return keyBytes;
	}

	// / <summary>
	// / Encrypts plaintext using AES 128bit key and a Chain Block Cipher and
	// returns a base64 encoded string
	// / </summary>
	// / <param name="plainText">Plain text to encrypt</param>
	// / <param name="key">Secret key</param>
	// / <returns>Base64 encoded string</returns>
	public String encrypt(String plainText, String key) throws UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		byte[] plainTextbytes = plainText.getBytes(characterEncoding);
		byte[] keyBytes = getKeyBytes(key);
		return Base64.encodeBase64String(encrypt(plainTextbytes, keyBytes, keyBytes));
	}



	public static void main(String[] args) throws KeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, GeneralSecurityException, IOException {
		String seed = "C4e4.d53.0fp4e.f3.4p53eq3.q3.z1.z1.z1.z1z1";
		String data = "4444555566667777";
		
		//EncryptarInterface service = null;
		
		//String outputOfDecrypt = service.encryptar(seed, data);
		
		CodigoAES128 d = new CodigoAES128();

		String outputOfDecrypt = d.encryptar(seed, data);
		
		System.out.println("[CryptoSecurity.outputOfDecrypt]: "+ outputOfDecrypt);

	}

	

}
