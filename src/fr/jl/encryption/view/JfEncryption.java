/*
 * Copyright (C) Jessica LASSIE from 2020 to present
 * All rights reserved
 */
package fr.jl.encryption.view;

import fr.jl.encryption.controller.ControllerEncryption;
import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JFileChooser;

/**
 *
 * @author Jessica LASSIE
 */
public class JfEncryption extends javax.swing.JFrame {
    
    private static final String AES = "AES";
    private static final String RSA = "RSA";

    /**
     * Creates new form NewJFrame
     */
    public JfEncryption() {
        initComponents();
        
        buttonGroup.add(jRadioButtonDecrypt);
        buttonGroup.add(jRadioButtonEncrypt);
        jRadioButtonEncrypt.setSelected(true);
        jComboBoxEncrypt.addItem(AES);
        jComboBoxEncrypt.addItem(RSA);
        jTextFieldKey.setEnabled(false);
        jDialogError.setSize(170, 140);
        jDialogSuccess.setSize(170, 140);
        jButtonStart.setEnabled(false);
        
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        buttonGroup = new javax.swing.ButtonGroup();
        jFileChooser = new javax.swing.JFileChooser();
        jDialogError = new javax.swing.JDialog();
        jLabelError = new javax.swing.JLabel();
        jButtonDialogError = new javax.swing.JButton();
        jDialogSuccess = new javax.swing.JDialog();
        jLabelSuccess = new javax.swing.JLabel();
        jButtonDialogSuccess = new javax.swing.JButton();
        jLabelFile = new javax.swing.JLabel();
        jButtonSearchFile = new javax.swing.JButton();
        jButtonStart = new javax.swing.JButton();
        jRadioButtonEncrypt = new javax.swing.JRadioButton();
        jRadioButtonDecrypt = new javax.swing.JRadioButton();
        jComboBoxEncrypt = new javax.swing.JComboBox<>();
        jLabelEncrypt = new javax.swing.JLabel();
        jTextFieldKey = new javax.swing.JTextField();
        jLabelKey = new javax.swing.JLabel();
        jLabelSelectedFile = new javax.swing.JLabel();

        jDialogError.setTitle("Erreur");

        jButtonDialogError.setText("OK");
        jButtonDialogError.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonDialogErrorActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jDialogErrorLayout = new javax.swing.GroupLayout(jDialogError.getContentPane());
        jDialogError.getContentPane().setLayout(jDialogErrorLayout);
        jDialogErrorLayout.setHorizontalGroup(
            jDialogErrorLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jDialogErrorLayout.createSequentialGroup()
                .addGroup(jDialogErrorLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jDialogErrorLayout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(jLabelError, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(jDialogErrorLayout.createSequentialGroup()
                        .addGap(59, 59, 59)
                        .addComponent(jButtonDialogError)))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        jDialogErrorLayout.setVerticalGroup(
            jDialogErrorLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jDialogErrorLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabelError)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 32, Short.MAX_VALUE)
                .addComponent(jButtonDialogError)
                .addContainerGap())
        );

        jDialogSuccess.setTitle("Success");

        jLabelSuccess.setText("Success");

        jButtonDialogSuccess.setText("OK");
        jButtonDialogSuccess.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonDialogSuccessActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jDialogSuccessLayout = new javax.swing.GroupLayout(jDialogSuccess.getContentPane());
        jDialogSuccess.getContentPane().setLayout(jDialogSuccessLayout);
        jDialogSuccessLayout.setHorizontalGroup(
            jDialogSuccessLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jDialogSuccessLayout.createSequentialGroup()
                .addGroup(jDialogSuccessLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jDialogSuccessLayout.createSequentialGroup()
                        .addContainerGap()
                        .addComponent(jLabelSuccess, javax.swing.GroupLayout.PREFERRED_SIZE, 150, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(jDialogSuccessLayout.createSequentialGroup()
                        .addGap(59, 59, 59)
                        .addComponent(jButtonDialogSuccess)))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        jDialogSuccessLayout.setVerticalGroup(
            jDialogSuccessLayout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jDialogSuccessLayout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabelSuccess)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 18, Short.MAX_VALUE)
                .addComponent(jButtonDialogSuccess)
                .addContainerGap())
        );

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setTitle("Encryption");
        setResizable(false);
        setSize(new java.awt.Dimension(431, 213));

        jLabelFile.setText("File");

        jButtonSearchFile.setText("...");
        jButtonSearchFile.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonSearchFileActionPerformed(evt);
            }
        });

        jButtonStart.setText("Start");
        jButtonStart.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                jButtonStartActionPerformed(evt);
            }
        });

        jRadioButtonEncrypt.setText("Encrypt");
        jRadioButtonEncrypt.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                jRadioButtonEncryptStateChanged(evt);
            }
        });

        jRadioButtonDecrypt.setText("Decrypt");
        jRadioButtonDecrypt.addChangeListener(new javax.swing.event.ChangeListener() {
            public void stateChanged(javax.swing.event.ChangeEvent evt) {
                jRadioButtonDecryptStateChanged(evt);
            }
        });

        jLabelEncrypt.setText("Algorythm");

        jLabelKey.setText("Key");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(41, 41, 41)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jTextFieldKey)
                    .addGroup(layout.createSequentialGroup()
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(jLabelEncrypt)
                            .addComponent(jComboBoxEncrypt, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addComponent(jLabelFile)
                            .addGroup(layout.createSequentialGroup()
                                .addComponent(jRadioButtonEncrypt)
                                .addGap(54, 54, 54)
                                .addComponent(jRadioButtonDecrypt))
                            .addComponent(jButtonStart)
                            .addComponent(jLabelKey))
                        .addGap(0, 55, Short.MAX_VALUE))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jButtonSearchFile)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(jLabelSelectedFile, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                .addGap(43, 43, 43))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(30, 30, 30)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jRadioButtonEncrypt)
                    .addComponent(jRadioButtonDecrypt))
                .addGap(18, 18, 18)
                .addComponent(jLabelKey)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jTextFieldKey, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 18, Short.MAX_VALUE)
                .addComponent(jLabelEncrypt)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jComboBoxEncrypt, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(18, 18, 18)
                .addComponent(jLabelFile)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jButtonSearchFile)
                    .addComponent(jLabelSelectedFile))
                .addGap(18, 18, 18)
                .addComponent(jButtonStart)
                .addGap(35, 35, 35))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void jButtonSearchFileActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonSearchFileActionPerformed
        final int value = jFileChooser.showOpenDialog(this);
        if(value == JFileChooser.APPROVE_OPTION){
            jFileChooser.getSelectedFile().getAbsolutePath();
            jLabelSelectedFile.setText(jFileChooser.getSelectedFile().getName());
            jButtonStart.setEnabled(true);
        }
    }//GEN-LAST:event_jButtonSearchFileActionPerformed

    private void jButtonStartActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonStartActionPerformed
        final String filePath = jFileChooser.getSelectedFile().getAbsolutePath();
        File inputFile = new File(filePath);
        switch (jComboBoxEncrypt.getSelectedItem().toString()) {
            case AES:
                if (jRadioButtonEncrypt.isSelected()) {
                    int mode = Cipher.ENCRYPT_MODE;
                    File outputFile = ControllerEncryption.preFormating(mode, filePath);
                    try {
                        SecretKey key = ControllerEncryption.generateAESKey();
                        File keyFile = ControllerEncryption.saveAESKey(key, outputFile.getParent());
                        if (key != null && keyFile.exists()){
                            ControllerEncryption.cryptingAES(mode, key, inputFile, outputFile);
                            jDialogSuccess.setVisible(true);
                        }                      
                    } catch (NoSuchAlgorithmException | IOException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex) {
                        jDialogError.setVisible(true);
                        jLabelError.setText(ex.getMessage());
                    }
                }
                if (jRadioButtonDecrypt.isSelected()) {
                    if (jTextFieldKey.getText().length() != 16) {
                        jDialogError.setVisible(true);
                        jLabelError.setText("Invalid key length");
                    } else {
                        int mode = Cipher.DECRYPT_MODE;
                        File outputFile = ControllerEncryption.preFormating(mode, filePath);
                        try {
                            byte[] decodedKey = Base64.getDecoder().decode(jTextFieldKey.getText());
                            SecretKey key = new SecretKeySpec(decodedKey, 0, decodedKey.length, AES); 
                            ControllerEncryption.cryptingAES(mode, key, inputFile, outputFile);
                            jDialogSuccess.setVisible(true);
                        } catch (IOException | InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException ex) {
                            jDialogError.setVisible(true);
                            jLabelError.setText(ex.getMessage());
                        }
                    }
                }
                break;
            case RSA:
                //TO DO
                break;
            default :
                break;
        }
    }//GEN-LAST:event_jButtonStartActionPerformed

    private void jRadioButtonDecryptStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_jRadioButtonDecryptStateChanged
        if (jRadioButtonDecrypt.isSelected()) {
            jTextFieldKey.setEnabled(true);
        }
    }//GEN-LAST:event_jRadioButtonDecryptStateChanged

    private void jRadioButtonEncryptStateChanged(javax.swing.event.ChangeEvent evt) {//GEN-FIRST:event_jRadioButtonEncryptStateChanged
        if (jRadioButtonEncrypt.isSelected()) {
            jTextFieldKey.setEnabled(false);
        }
    }//GEN-LAST:event_jRadioButtonEncryptStateChanged

    private void jButtonDialogErrorActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonDialogErrorActionPerformed
        jDialogError.setVisible(false);
    }//GEN-LAST:event_jButtonDialogErrorActionPerformed

    private void jButtonDialogSuccessActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_jButtonDialogSuccessActionPerformed
        jDialogSuccess.setVisible(false);
    }//GEN-LAST:event_jButtonDialogSuccessActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException | javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(JfEncryption.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>
        //</editor-fold>
        
        //</editor-fold>
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(() -> {
            new JfEncryption().setVisible(true);
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.ButtonGroup buttonGroup;
    private javax.swing.JButton jButtonDialogError;
    private javax.swing.JButton jButtonDialogSuccess;
    private javax.swing.JButton jButtonSearchFile;
    private javax.swing.JButton jButtonStart;
    private javax.swing.JComboBox<String> jComboBoxEncrypt;
    private javax.swing.JDialog jDialogError;
    private javax.swing.JDialog jDialogSuccess;
    private javax.swing.JFileChooser jFileChooser;
    private javax.swing.JLabel jLabelEncrypt;
    private javax.swing.JLabel jLabelError;
    private javax.swing.JLabel jLabelFile;
    private javax.swing.JLabel jLabelKey;
    private javax.swing.JLabel jLabelSelectedFile;
    private javax.swing.JLabel jLabelSuccess;
    private javax.swing.JRadioButton jRadioButtonDecrypt;
    private javax.swing.JRadioButton jRadioButtonEncrypt;
    private javax.swing.JTextField jTextFieldKey;
    // End of variables declaration//GEN-END:variables
}
