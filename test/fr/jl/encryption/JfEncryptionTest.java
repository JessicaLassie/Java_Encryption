/*
 * Copyright (C) Jessica LASSIE from 2020 to present
 * All rights reserved
 */
package fr.jl.encryption;

import fr.jl.encryption.controller.ControllerEncryption;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 *
 * @author Jessica LASSIE
 */
public class JfEncryptionTest {
    
    private final static int ENCRYPT_MODE = Cipher.ENCRYPT_MODE;
    private final static String FILE_PATH = "test\\fr\\jl\\encryption\\resources\\doc.txt";
    
    public JfEncryptionTest() {
    }
    
    @BeforeClass
    public static void setUpClass() {
    }
    
    @AfterClass
    public static void tearDownClass() {
    }
    
    @Before
    public void setUp() {
    }
    
    @After
    public void tearDown() {
    }

    @Test
    public void testCrypting() throws NoSuchAlgorithmException, IOException, FileNotFoundException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        ControllerEncryption.encryptAES(ENCRYPT_MODE, FILE_PATH);
    }
}
