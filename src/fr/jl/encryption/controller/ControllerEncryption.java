/*
 * Copyright (C) Jessica LASSIE from 2020 to present
 * All rights reserved
 */
package fr.jl.encryption.controller;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Date;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Jessica LASSIE
 */
public class ControllerEncryption {
    
    private static final String AES = "AES";
    private static final String RSA = "RSA";
    
    private ControllerEncryption() { 
    };
    
    /**
     * Encrypt a file in AES
     * @param mode encrypt or decrypt mode
     * @param filePath file path of input file for output file
     * @param inputFile file to encrypt
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws FileNotFoundException
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException 
     */
    public static void encryptAES(final int mode, final String filePath, final File inputFile) throws NoSuchAlgorithmException, IOException, FileNotFoundException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        File outputFile = preFormating(mode, filePath);
        SecretKey key = generateAESKey();
        File keyFile = saveAESKey(key, outputFile.getParent());
        if (key != null && keyFile.exists()){
            crypting(mode, key, inputFile, outputFile, AES);
        }       
    }
    
    /**
     * Decrypt a file in AES
     * @param mode encrypt or decrypt mode
     * @param filePath file path of input file for output file
     * @param keyFilePath path for save the key file
     * @param inputFile file to decrypt
     * @throws FileNotFoundException
     * @throws IOException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException 
     */
    public static void decryptAES(final int mode, final String filePath, final String keyFilePath, final File inputFile) throws FileNotFoundException, IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        File outputFile = preFormating(mode, filePath);
        BufferedReader reader = new BufferedReader(new FileReader(keyFilePath));
	String line;
        String contentFile = "";
	while ((line = reader.readLine()) != null) {
            contentFile = line;
	}
        byte[] decodedKey = Base64.getDecoder().decode(contentFile);
        SecretKey key = new SecretKeySpec(decodedKey, 0, decodedKey.length, AES); 
        crypting(mode, key, inputFile, outputFile, AES);
    }
    
    /**
     * Encrypt a file in RSA
     * @param mode encrypt or decrypt mode
     * @param filePath file path of input file for output file
     * @param inputFile file to encrypt
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws FileNotFoundException
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException 
     */
    public static void encryptRSA(final int mode, final String filePath, final File inputFile) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException, FileNotFoundException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        File outputFile = preFormating(mode, filePath);
        KeyPair keyPair = generateRSAKey();
        File privateKeyFile = saveRSAPrivateKey(keyPair.getPrivate(), outputFile.getParent());
        if (privateKeyFile.exists()){
            crypting(mode, keyPair.getPublic(), inputFile, outputFile, RSA);
        }                      
    }
    
    /**
     * Decrypt a file in RSA
     * @param mode encrypt or decrypt mode
     * @param filePath file path of input file for output file
     * @param keyFilePath path for save the key file
     * @param inputFile file to decrypt
     * @throws IOException
     * @throws FileNotFoundException
     * @throws ClassNotFoundException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException 
     */
    public static void decryptRSA(final int mode, final String filePath, final String keyFilePath, final File inputFile) throws IOException, FileNotFoundException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        File outputFile = preFormating(mode, filePath);
        PrivateKey privateKey = getRSAPrivateKey(keyFilePath);
        if (privateKey != null) {
            crypting(mode, privateKey, inputFile, outputFile, RSA);
        }
    }
    
    /**
     * Create format file
     * @param mode encrypt or decrypt mode
     * @param filePath file path of input file for output file
     * @return file for encrypt or decrypt output
     */
    private static File preFormating(final int mode, final String filePath) {
        SimpleDateFormat formater = new SimpleDateFormat("yyyyMMddHHmmss");
        final String date = formater.format(new Date());
        final int pos = filePath.indexOf('.');
        String modeType = "";
        switch (mode) {
            case 1:
                modeType = "_encrypted_";
                break;
            case 2:
                modeType = "_decrypted_";
                break;
            default :
                break;
        }
        return new File(filePath.substring(0, pos) + modeType + date + filePath.substring(pos, filePath.length()));
    }
    
    /**
     * Generate key in 128 bits for AES encryption
     * @return key in 128 bits
     * @throws NoSuchAlgorithmException 
     */
    private static SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance(AES);
        keyGen.init(128);
        SecretKey secretKey = keyGen.generateKey();
        return secretKey;
    }
    
    /**
     * Save key in a text file
     * @param key in 128 bits
     * @param keyFilePath path for save the key file
     * @return file with key
     * @throws IOException
     */
    private static File saveAESKey(final SecretKey key, final String keyFilePath) throws IOException {
        SimpleDateFormat formater = new SimpleDateFormat("yyyyMMddHHmmss");
        final String date = formater.format(new Date());
        File keyFile = new File(keyFilePath + "\\key_" + date + ".txt");
        FileWriter fw = new FileWriter(keyFile.getAbsoluteFile());
        try (BufferedWriter bw = new BufferedWriter(fw)) {
            byte encoded[] = key.getEncoded();
            final String encodedKey = Base64.getEncoder().encodeToString(encoded);
            keyFile.createNewFile();
            bw.write(encodedKey);
        }
        return keyFile;
    }
    
    /**
     * Generate key pair for RSA crypting
     * @return keys pair (private key and public key)
     */
    private static KeyPair generateRSAKey() {
        KeyPairGenerator keyGenerator = null;
        KeyPair keyPair = null;
        try {
            keyGenerator = KeyPairGenerator.getInstance(RSA);
            keyGenerator.initialize(2048);
        } catch (NoSuchAlgorithmException ex) {
            
        }
        if (keyGenerator != null) {
            keyPair = keyGenerator.generateKeyPair();           
        }
        return keyPair;
    }
    
    /**
     * Save private key in a text file
     * @param privateKey
     * @param privateKeyFilePath
     * @return file with private key
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException 
     * @throws FileNotFoundException 
     */
    private static File saveRSAPrivateKey(final PrivateKey privateKey, final String privateKeyFilePath) throws InvalidKeySpecException, NoSuchAlgorithmException, FileNotFoundException, IOException {
        SimpleDateFormat formater = new SimpleDateFormat("yyyyMMddHHmmss");
        final String date = formater.format(new Date());
        File privateKeyFile = new File(privateKeyFilePath + "\\key_" + date + ".txt");
        KeyFactory factory = KeyFactory.getInstance(RSA);
        RSAPrivateKeySpec specification = factory.getKeySpec(privateKey, RSAPrivateKeySpec.class);
        if (specification != null) {
            try (ObjectOutputStream outputFile = new ObjectOutputStream(new BufferedOutputStream(new FileOutputStream(privateKeyFile)))) {
                outputFile.writeObject(specification.getModulus());
                outputFile.writeObject(specification.getPrivateExponent());
            }              
        }
        return privateKeyFile;
    }
    
    /**
     * Get privte key for decrypt in RSA
     * @param keyFilePath private key file path
     * @return private key
     * @throws FileNotFoundException
     * @throws IOException
     * @throws ClassNotFoundException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException 
     */
    private static PrivateKey getRSAPrivateKey(final String keyFilePath) throws FileNotFoundException, IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException {
        PrivateKey privateKey = null;
        try (ObjectInputStream ois = new ObjectInputStream(new BufferedInputStream(new FileInputStream(keyFilePath)))) {
            BigInteger modulo = (BigInteger) ois.readObject();
            BigInteger exposant = (BigInteger) ois.readObject();
            RSAPrivateKeySpec specification = new RSAPrivateKeySpec(modulo, exposant);
            KeyFactory factory = KeyFactory.getInstance(RSA);
            privateKey = factory.generatePrivate(specification);
        }       
        return privateKey;
    }
    
    /**
     * Encrypt or decrypt a file
     * @param mode encrypt or decrypt mode
     * @param key key for encrypt or decrypt
     * @param inputFile file to encrypt or decrypt
     * @param outputFile encrypted file or decrypted file
     * @param algorithm of crypting
     * @throws FileNotFoundException
     * @throws IOException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException 
     */    
    private static void crypting(final int mode, final Key key, File inputFile, File outputFile, final String algorithm) throws FileNotFoundException, IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        try (FileInputStream inputStream = new FileInputStream(inputFile); FileOutputStream outputStream = new FileOutputStream(outputFile)) {
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(mode, key);
            byte[] inputBytes = new byte[inputStream.available()];
            while (inputStream.read(inputBytes) > -1) {
                byte[] outputBytes = cipher.doFinal(inputBytes);
                outputStream.write(outputBytes);
            }
        }
    }
    
}
