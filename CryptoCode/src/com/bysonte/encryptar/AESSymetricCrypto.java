package com.bysonte.encryptar;

import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

import sun.misc.BASE64Encoder;


public class AESSymetricCrypto {

   public static void main(String[] args) throws Exception {

      // Generamos una clave de 128 bits adecuada para AES
      KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
      keyGenerator.init(256);
      Key key = keyGenerator.generateKey();
      String llaveMagica = "#C4e4.d53.0fp4e.f3.4p53eq3.q3.z1";
      
      // Alternativamente, una clave que queramos que tenga al menos 16 bytes
      // y nos quedamos con los bytes 0 a 15
      key = new SecretKeySpec(llaveMagica.getBytes(),  0, 32, "AES");
      
      // Ver como se puede guardar esta clave en un fichero y recuperarla
      // posteriormente en la clase RSAAsymetricCrypto.java

      // Texto a encriptar
      String texto = "4444555566667777";
      System.out.println("Texto original: " + texto);

      // Se obtiene un cifrador AES
      Cipher aes = Cipher.getInstance("AES/ECB/PKCS5Padding");

      // Se inicializa para encriptacion y se encripta el texto,
      // que debemos pasar como bytes.
      aes.init(Cipher.ENCRYPT_MODE, key);
      byte[] encriptado = aes.doFinal(texto.getBytes());

      String s = new BASE64Encoder().encode(encriptado);
      System.out.println("encrypted string base64: " + s);
      
      // Se escribe byte a byte en hexadecimal el texto
      // encriptado para ver su pinta.
      System.out.print("Texto encriptado: ");
      for (byte b : encriptado) {
         System.out.print(Integer.toHexString(0xFF & b));
      }
      System.out.println();
      // Se iniciliza el cifrador para desencriptar, con la
      // misma clave y se desencripta
      aes.init(Cipher.DECRYPT_MODE, key);
      byte[] desencriptado = aes.doFinal(encriptado);

      // Texto obtenido, igual al original.
      System.out.println("Texto desencriptado: " + new String(desencriptado));
   }
}