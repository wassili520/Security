package com.wassili.hmac;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

public class WassiliHmac {
	
	private static String src = "wassili security md"; 
	
	public static void main(String[] args) {
		jdkHmacMD5();
		bcHmacMD5();
	}
	
	public static void jdkHmacMD5() {
		try {
			KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacMD5");//初始化KeyGenerator
			SecretKey secretKey = keyGenerator.generateKey();//产生秘钥
			byte[] key = secretKey.getEncoded();//获得秘钥
			
//			byte[] key = Hex.decodeHex(new char[]{'a','a','a','a','a','a','a','a','a','a'});
			
			SecretKey restorSecretKey = new SecretKeySpec(key, "HmacMD5");//还原秘钥
			Mac mac = Mac.getInstance(restorSecretKey.getAlgorithm());//实例化mac
			mac.init(restorSecretKey);//初始化mac
			byte[] hmacMD5Bytes = mac.doFinal(src.getBytes());//执行摘要
			System.out.println("jdk hamcMD5: " + Hex.encodeHexString(hmacMD5Bytes));
			System.out.println("jdk hamcMD5: " + byte2hex(hmacMD5Bytes));
			System.out.println("jdk hamcMD5: " + byte2hex1(hmacMD5Bytes));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	/**
	 * 对bytes进行16进制转换
	 * @param bytes
	 * @return
	 */
	public static String byte2hex(byte[] bytes) {
		StringBuilder sign = new StringBuilder();
		for (int i = 0; i < bytes.length; i++) {
			String hex = Integer.toHexString(bytes[i] & 0xFF);
			if (hex.length() == 1) {
				sign.append("0");
			}
			sign.append(hex);
		}
		return sign.toString();
	}
	
	/**
	 * 对bytes进行16进制转换并且转换大写
	 * @param bytes
	 * @return
	 */
	public static String byte2hex1(byte[] bytes) {
		StringBuilder sign = new StringBuilder();
		for (int i = 0; i < bytes.length; i++) {
			String hex = Integer.toHexString(bytes[i] & 0xFF);
			if (hex.length() == 1) {
				sign.append("0");
			}
			sign.append(hex.toUpperCase());
		}
		return sign.toString();
	}
	
	
	public static void bcHmacMD5() {
		HMac hMac = new HMac(new MD5Digest());
		hMac.init(new KeyParameter(org.bouncycastle.util.encoders.Hex.decode("aaaaaaaaaa")));
		hMac.update(src.getBytes(), 0, src.getBytes().length);
		
		byte[] hmacMD5Bytes = new byte[hMac.getMacSize()];//执行摘要
		hMac.doFinal(hmacMD5Bytes, 0);
		
		System.out.println("bc hamcMD5: " + org.bouncycastle.util.encoders.Hex.toHexString(hmacMD5Bytes));
	}

}
