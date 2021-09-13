package com.arover.ext.decryptor;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

import com.arover.app.crypto.AesCbcCipher;
import com.arover.app.crypto.RsaCipher;

public class Decryptor {
	
	@SuppressWarnings("resource")
	public static File decryptLogFile(File privateKeyFile, File encryptedLogFile) throws Exception {
        
		if (null == encryptedLogFile || null == privateKeyFile) {
			throw new NullPointerException("encryptedLogFile / privateKey can't be null");
		}
		
		byte[] privateKeyBuffer = new byte[2048];
		int privateKeyLen = new FileInputStream(privateKeyFile).read(privateKeyBuffer);
		if (privateKeyLen <= 1024) {
			throw new IllegalStateException("length too small, are you sure private key is correct?");
		}
		
		byte[] privateKey = new byte[privateKeyLen];
		System.arraycopy(privateKeyBuffer, 0, privateKey, 0, privateKeyLen);
		
		DataInputStream in = new DataInputStream(new FileInputStream(encryptedLogFile));

		File outputFile = new File(encryptedLogFile.getAbsolutePath() + "_decrypted_" + System.currentTimeMillis() + ".log");
		outputFile.createNewFile();
        
		FileOutputStream out = new FileOutputStream(outputFile);
        
        try {
        	
            byte[] buf;
            byte[] iv = new byte[256]; // magic iv length
            byte[] key = new byte[256]; // magic key length
            int n;
            
            for (; ; ) {
            	int len = 0;
            	try {
            		len = in.readInt();
            	} catch (EOFException e) {
            		// end of file, simply break here
            		break;
            	}
                
                if(len > 131072 /*1024 * 128*/){
                	throw new IllegalStateException("length (" + len + ") excceed buffer max, are you sure file is correct?");
                }
                
                byte mode = in.readByte();
                
                if (mode == 1 /*magic: encrypt log mode*/) {
                    n = in.read(iv);
                    if (n != iv.length) {
                        throw new IllegalStateException("read iv data error n != iv.length.");
                    }
                    
                    n = in.read(key);
                    if (n != key.length) {
                        throw new IllegalStateException("read key data error n != key.length.");
                    }
                }
                
                buf = new byte[len];
                n = in.read(buf);
                if (n != len) {
                    throw new IllegalStateException("read log data error, read log length is not equals len.");
                }
                
                if (mode == 1 /*magic: encrypt log mode*/) {
                    byte[] decryptLog;
                    try {
                        
                    	byte[] decryptKey = RsaCipher.decrypt(key, privateKey);
                        byte[] decryptIv = RsaCipher.decrypt(iv, privateKey);
                        
                        decryptLog = AesCbcCipher.decrypt(buf, decryptKey, decryptIv);
                        out.write(decryptLog);
                        
                    } catch (Exception e) {
                    	new IllegalStateException("error decrypting encrypted log part, leave this part as-is", e).printStackTrace();
                        out.write(buf);
                    }
                } else {
                    out.write(buf);
                }
            }

        } catch (Exception e) {
            throw e;
        } finally {
            
        	try {
            	in.close();
            } catch (Exception ignored) {}
            
            try {
            	out.flush();
            	out.close();
            } catch (Exception ignored) {}
        }
        
        return outputFile;

    }
}
