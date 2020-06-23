/*
 * Copyright (C) Jessica LASSIE from 2020 to present
 * All rights reserved
 */
package fr.jl.encryption.controller;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
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
     * Create format file
     * @param mode encrypt or decrypt mode
     * @param filePath file path of input file for output file
     * @return file for encrypt or decrypt output
     */
    public static File preFormating(final int mode, final String filePath) {
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
    public static SecretKey generateAESKey() throws NoSuchAlgorithmException {
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
    public static File saveAESKey(final SecretKey key, final String keyFilePath) throws IOException {
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
    public static KeyPair generateRSAKey() {
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
    public static File saveRSAPrivateKey(final PrivateKey privateKey, final String privateKeyFilePath) throws InvalidKeySpecException, NoSuchAlgorithmException, FileNotFoundException, IOException {
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
    public static PrivateKey getRSAPrivateKey(final String keyFilePath) throws FileNotFoundException, IOException, ClassNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException {
        BigInteger modulo = null;
        BigInteger exposant = null;
        PrivateKey privateKey = null;
        try (ObjectInputStream ois = new ObjectInputStream(new BufferedInputStream(new FileInputStream(keyFilePath)))) {
            modulo = (BigInteger) ois.readObject();
            exposant = (BigInteger) ois.readObject();
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
    public static void crypting(final int mode, final Key key, File inputFile, File outputFile, final String algorithm) throws FileNotFoundException, IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
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
