package com.wassili.des;


import java.security.Key;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class WassiliDES {
	
	private static String src = "wassili security des";

	public static void main(String[] args) {
		jdkDES();
		bcDes();
	}

	public static void jdkDES() {
		KeyGenerator keyGenerator;
		try {
			//生成key
			keyGenerator = KeyGenerator.getInstance("DES");
			keyGenerator.init(56);
			SecretKey secretKey= keyGenerator.generateKey();
			byte[] bytesKey = secretKey.getEncoded();
			
			//key转换
			DESKeySpec desKeySpec = new DESKeySpec(bytesKey);
			SecretKeyFactory factory= SecretKeyFactory.getInstance("DES");
			Key convertSecretKey= factory.generateSecret(desKeySpec);
			
			//加密
			Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, convertSecretKey);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("jdk des encrypt : " + Hex.encodeHexString(result));
			
			cipher.init(Cipher.DECRYPT_MODE, convertSecretKey);
			result = cipher.doFinal(result);
			System.out.println("jdk des decrypt : " + new String(result));
			
			
			
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	public static void  bcDes() {
		KeyGenerator keyGenerator;
		try {
			Security.addProvider(new BouncyCastleProvider());
			
			//生成key
			keyGenerator = KeyGenerator.getInstance("DES","BC");
			keyGenerator.getProvider();
			keyGenerator.init(56);
			SecretKey secretKey= keyGenerator.generateKey();
			byte[] bytesKey = secretKey.getEncoded();
			
			//key转换
			DESKeySpec desKeySpec = new DESKeySpec(bytesKey);
			SecretKeyFactory factory= SecretKeyFactory.getInstance("DES");
			Key convertSecretKey= factory.generateSecret(desKeySpec);
			
			//加密
			Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, convertSecretKey);
			byte[] result = cipher.doFinal(src.getBytes());
			System.out.println("bc des encrypt : " + Hex.encodeHexString(result));
			
			cipher.init(Cipher.DECRYPT_MODE, convertSecretKey);
			result = cipher.doFinal(result);
			System.out.println("bc des decrypt : " + new String(result));
			
			
			
			
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
