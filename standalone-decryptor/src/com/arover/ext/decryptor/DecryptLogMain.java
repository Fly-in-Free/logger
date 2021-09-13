package com.arover.ext.decryptor;

import java.io.File;
import java.util.Date;

public class DecryptLogMain {
	
	public static void main(String[] args) {
		
		if (args.length != 2) {
			printHelp("Parameter error.");
			return;
		}
		
		String privateKeyPath = args[0];
		File privateKeyFile = new File(privateKeyPath);
		
		if (!privateKeyFile.exists()) {
			printHelp("Private key not exist.");
			return;
		} else {
			outLine("Private key: " + privateKeyFile.getAbsolutePath());
		}
		
		String encryptedLogPath = args[1];
		File encryptedLogFile = new File(encryptedLogPath);
		
		if (!encryptedLogFile.exists()) {
			printHelp("Encrypted log file not exist.");
			return;
		} else {
			outLine("Encrypted log file: " + encryptedLogFile.getAbsolutePath());
		}
		
		File outputFile = null;
		
		try {
			outputFile = Decryptor.decryptLogFile(privateKeyFile, encryptedLogFile);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		if (null != outputFile) {
			outLine("Done, output file: " + outputFile.getAbsolutePath());
		} else {
			outLine("Done, but output file is null");
		}
		
	}
	
	private static void printHelp(String msg) {
		outLine(msg + " Usage: java -jar Decrypt.jar <privateKeyFile> <encryptedLogFile>");
	}
	
	private static void outLine(String msg) {
		String content = String.format("DecryptLogMain [%s] > %s", new Date().toString(), msg);
		System.out.println(content);
	}
	
}
