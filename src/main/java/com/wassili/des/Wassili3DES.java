package com.wassili.des;

import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Wassili3DES {
	private static String src = "wassili security des";

	public static void main(String[] args) {
		jdk3DES();
		bc3DES();
	}
	
	public static void jdk3DES() {
		KeyGenerator keyGenerator;
		try {
			//生成key
			keyGenerator = KeyGenerator.getInstance("DESede");
//			keyGenerator.init(168);
			keyGenerator.init(new SecureRandom());
			SecretKey secretKey= keyGenerator.generateKey();
			byte[] bytesKey = secretKey.getEncoded();
			
			//key转换
			DESedeKeySpec desKeySpec = new DESedeKeySpec(bytesKey);
			SecretKeyFactory factory= SecretKeyFactory.getInstance("DESede");
			Key convertSecretKey= factory.generateSecret(desKeySpec);
			
			//加密
			Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, convertSecretKey);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("jdk 3des encrypt : " + Hex.encodeHexString(result));
			
			cipher.init(Cipher.DECRYPT_MODE, convertSecretKey);
			result = cipher.doFinal(result);
			System.out.println("jdk 3des decrypt : " + new String(result));
			
			
			
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	public static void bc3DES() {
		KeyGenerator keyGenerator;
		try {
			Security.addProvider(new BouncyCastleProvider());
			//生成key
			keyGenerator = KeyGenerator.getInstance("DESede","BC");
			keyGenerator.getProvider();
//			keyGenerator.init(168);
			keyGenerator.init(new SecureRandom());
			SecretKey secretKey= keyGenerator.generateKey();
			byte[] bytesKey = secretKey.getEncoded();
			
			//key转换
			DESedeKeySpec desKeySpec = new DESedeKeySpec(bytesKey);
			SecretKeyFactory factory= SecretKeyFactory.getInstance("DESede");
			Key convertSecretKey= factory.generateSecret(desKeySpec);
			
			//加密
			Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, convertSecretKey);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("jdk 3des encrypt : " + Hex.encodeHexString(result));
			
			cipher.init(Cipher.DECRYPT_MODE, convertSecretKey);
			result = cipher.doFinal(result);
			System.out.println("jdk 3des decrypt : " + new String(result));
			
			
			
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
}
