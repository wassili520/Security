package com.wassili.md;

import java.security.MessageDigest;
import java.security.Security;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class WassiliMD {
	
	private static String src = "wassili security md";

	public static void main(String[] args) {
		jdkMD5();
		jdkMD2();
		bcMD5();
		bcMD4();
		ccMD5();

	}
	
	public static void jdkMD5() {
		try {
			MessageDigest md = MessageDigest.getInstance("MD5");
			byte[] md5Bytes = md.digest(src.getBytes());
//			System.out.println(new String(md5Bytes));
			System.out.println("JDK MD5: " + Hex.encodeHexString(md5Bytes));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	public static void jdkMD2() {
		try {
			MessageDigest md = MessageDigest.getInstance("MD2");
			byte[] md2Bytes = md.digest(src.getBytes());
			System.out.println("JDK MD2: " + Hex.encodeHexString(md2Bytes));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	public static void bcMD5() {
		try {
			Digest digest = new MD5Digest();
			digest.update(src.getBytes(), 0, src.getBytes().length);
			byte[] md5Bytes = new byte[digest.getDigestSize()];
			digest.doFinal(md5Bytes, 0);
			System.out.println("BC MD5: " + org.bouncycastle.util.encoders.Hex.toHexString(md5Bytes));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	public static void bcMD4() {
		
		try {
			Security.addProvider(new BouncyCastleProvider());
			MessageDigest md = MessageDigest.getInstance("MD4");
			byte[] md4Bytes = md.digest(src.getBytes());
			System.out.println("JDK MD4: " + Hex.encodeHexString(md4Bytes));
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	public static void ccMD5() {
		System.out.println("CC MD5: " + DigestUtils.md5Hex(src.getBytes()));
	}
	

}
