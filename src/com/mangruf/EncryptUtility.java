/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package com.mangruf;

import com.sun.mail.util.BASE64DecoderStream;
import com.sun.mail.util.BASE64EncoderStream;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.management.openmbean.InvalidKeyException;

/**
 *
 * @author Oluwatobi
 */
public class EncryptUtility {
    
    private static final int iterationCount = 10;
    private static String passPhrase = "My Secret Password";
    // 8-byte Salt
    private static byte[] salt = {
  (byte)0xB2, (byte)0x12, (byte)0xD5, (byte)0xB2,
  (byte)0x44, (byte)0x21, (byte)0xC3, (byte)0xC3
    };

    public String Encrypt(String message) throws java.security.InvalidKeyException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
            byte[] textEncrypted = {};
            String tx = "";
            try{

//                KeyGenerator keygenerator = KeyGenerator.getInstance("DES");
//                SecretKey myDesKey = keygenerator.generateKey();
//
//                Cipher desCipher;
//
//                // Create the cipher 
//                desCipher = Cipher.getInstance("DES");
//
//                // Initialize the cipher for encryption
//                desCipher.init(Cipher.ENCRYPT_MODE, myDesKey);
                
	            // provide password, salt, iteration count for generating PBEKey of fixed-key-size PBE ciphers
	            KeySpec keySpec = new PBEKeySpec(passPhrase.toCharArray(), salt, iterationCount);
	            // create a secret (symmetric) key using PBE with MD5 and DES
	            SecretKey key = SecretKeyFactory.getInstance("PBEWithMD5AndDES").generateSecret(keySpec);
	            // construct a parameter set for password-based encryption as defined in the PKCS #5 standard
	            AlgorithmParameterSpec paramSpec = new PBEParameterSpec(salt, iterationCount);
	            Cipher ecipher = Cipher.getInstance(key.getAlgorithm());
	            // initialize the ciphers with the given key
	  ecipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);

                //sensitive information
                byte[] text = message.getBytes("UTF8");

//                System.out.println("Text [Byte Format] : " + text);
//                System.out.println("Text : " + new String(text));

                // Encrypt the text
                textEncrypted = ecipher.doFinal(text);
                
                // encode to base64
                textEncrypted = BASE64EncoderStream.encode(textEncrypted);
//                System.out.println("Text Encryted : " + textEncrypted);
                System.out.println("Text Array : " + new String(textEncrypted));
                tx = new String(textEncrypted);
            }catch(Exception e){
                e.printStackTrace();
            }
//            }catch(NoSuchAlgorithmException e){
//                    e.printStackTrace();
//            }catch(NoSuchPaddingException e){
//                    e.printStackTrace();
//            }catch(InvalidKeyException e){
//                    e.printStackTrace();
//            }catch(IllegalBlockSizeException e){
//                    e.printStackTrace();
//            }catch(BadPaddingException e){
//                    e.printStackTrace();
//            }
       return tx;
    }
    
    
    public byte[] Decrypt(String encryptedText) throws java.security.InvalidKeyException
    {
//        byte [] text = encryptedText.getBytes();
	    // decode with base64 to get bytes
	byte[] dec = BASE64DecoderStream.decode(encryptedText.getBytes());
//        String response = encryptedText;
        
//        byte[] bytes = Base64.getDecoder().decode(encryptedText);
//        String[] byteValues = response.substring(1, response.length() - 1).split(",");
//        byte[] bytes = new byte[byteValues.length];
//
//        for (int i=0, len=bytes.length; i<len; i++) {
//           bytes[i] = Byte.parseByte(byteValues[i].trim());     
//        }
        
//        byte [] text = response.getBytes();
        byte [] text = dec;
        byte[] textDecrypted = {};
        try {
            
//            KeyGenerator keygenerator = KeyGenerator.getInstance("DES");
//            SecretKey myDesKey = keygenerator.generateKey();
//
//            Cipher desCipher;
//
//            // Create the cipher 
//            desCipher = Cipher.getInstance("DES");
//
//            // Initialize the cipher for decryption
//            desCipher.init(Cipher.DECRYPT_MODE, myDesKey);

	            // provide password, salt, iteration count for generating PBEKey of fixed-key-size PBE ciphers
	            KeySpec keySpec = new PBEKeySpec(passPhrase.toCharArray(), salt, iterationCount);
	            // create a secret (symmetric) key using PBE with MD5 and DES
	            SecretKey key = SecretKeyFactory.getInstance("PBEWithMD5AndDES").generateSecret(keySpec);
	            // construct a parameter set for password-based encryption as defined in the PKCS #5 standard
	            AlgorithmParameterSpec paramSpec = new PBEParameterSpec(salt, iterationCount);
	            Cipher dcipher = Cipher.getInstance(key.getAlgorithm());
	            // initialize the ciphers with the given key
	  dcipher.init(Cipher.DECRYPT_MODE, key, paramSpec);
            // Decrypt the text
            textDecrypted = dcipher.doFinal(text);
            
            System.out.println(text);
            System.out.println("Text Decryted : " + new String(textDecrypted));

        }catch(Exception e){
                e.printStackTrace();
        }

        return textDecrypted;
    }
    public static void main(String[] args) throws java.security.InvalidKeyException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
        EncryptUtility utility = new EncryptUtility();
        String enc = utility.Encrypt("test");
        byte[] dec = utility.Decrypt(enc);
        System.out.println(enc);
        System.out.println(dec);
        System.out.println("Decrypted -- "+new String(dec, "UTF8"));
    }
}
