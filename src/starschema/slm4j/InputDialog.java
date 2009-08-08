/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

/*
 * InputDialog.java
 *
 * Created on 2009.08.04., 20:50:33
 */
package starschema.slm4j;

import java.io.File;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.filechooser.FileNameExtensionFilter;

/**
 *
 * @author Admin
 */
public class InputDialog extends javax.swing.JDialog {

    /** Creates new form InputDialog */
    public InputDialog(java.awt.Frame parent, boolean modal) {
        super(parent, modal);
        initComponents();

        jLabel.setText("License file:");
        jLabel2.setText("Signed license file:");
        jLabel3.setText("Public key file:");
        jLabel4.setText("Private key file:");

        jLabel.setVisible(true);
        jLabel2.setVisible(true);
        jLabel3.setVisible(true);
        jLabel4.setVisible(true);

        jTextField.setVisible(true);
        jTextField2.setVisible(true);
        jTextField3.setVisible(true);
        jTextField4.setVisible(true);

        browseButton.setVisible(true);
        browseButton2.setVisible(true);
        browseButton3.setVisible(true);
        browseButton4.setVisible(true);

        actionButton.setText("Sign license");
    }

    /** This method is called from within the constructor to
     * initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is
     * always regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        buttonGroup = new javax.swing.ButtonGroup();
        actionButton = new javax.swing.JButton();
        closeButton = new javax.swing.JButton();
        jPanel1 = new javax.swing.JPanel();
        jLabel4 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        jLabel = new javax.swing.JLabel();
        jTextField3 = new javax.swing.JTextField();
        browseButton3 = new javax.swing.JButton();
        jTextField4 = new javax.swing.JTextField();
        browseButton4 = new javax.swing.JButton();
        jTextField2 = new javax.swing.JTextField();
        jTextField = new javax.swing.JTextField();
        browseButton = new javax.swing.JButton();
        browseButton2 = new javax.swing.JButton();
        jPanel2 = new javax.swing.JPanel();
        signRadioButton = new javax.swing.JRadioButton();
        validateRadioButton = new javax.swing.JRadioButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        setTitle("Signature Creator and Validator");

        actionButton.setText("Ok");
        actionButton.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                actionButtonClicked(evt);
            }
        });

        closeButton.setText("Close");
        closeButton.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                closeClicked(evt);
            }
        });

        jPanel1.setBorder(new javax.swing.border.LineBorder(new java.awt.Color(153, 153, 153), 1, true));

        jLabel4.setText("Private key file:");

        jLabel2.setText("Signature file:");

        jLabel3.setText("Public key file:");

        jLabel.setText("License file:");

        browseButton3.setText("Browse");
        browseButton3.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                browseFile3(evt);
            }
        });

        browseButton4.setText("Browse");
        browseButton4.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                browseFile4(evt);
            }
        });

        browseButton.setText("Browse");
        browseButton.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                browseFile(evt);
            }
        });

        browseButton2.setText("Browse");
        browseButton2.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                browseFile2(evt);
            }
        });

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel4)
                    .addComponent(jLabel2)
                    .addComponent(jLabel3)
                    .addComponent(jLabel))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                        .addComponent(jTextField3, javax.swing.GroupLayout.DEFAULT_SIZE, 401, Short.MAX_VALUE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(browseButton3))
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addComponent(jTextField4, javax.swing.GroupLayout.DEFAULT_SIZE, 401, Short.MAX_VALUE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(browseButton4))
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel1Layout.createSequentialGroup()
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(jTextField2, javax.swing.GroupLayout.DEFAULT_SIZE, 401, Short.MAX_VALUE)
                            .addComponent(jTextField, javax.swing.GroupLayout.DEFAULT_SIZE, 401, Short.MAX_VALUE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(browseButton)
                            .addComponent(browseButton2))))
                .addContainerGap())
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel)
                    .addComponent(jTextField, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(browseButton))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel2)
                    .addComponent(jTextField2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(browseButton2))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel3)
                    .addComponent(jTextField3, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(browseButton3))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel4)
                    .addComponent(jTextField4, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(browseButton4))
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        jPanel2.setBorder(new javax.swing.border.LineBorder(new java.awt.Color(153, 153, 153), 1, true));

        buttonGroup.add(signRadioButton);
        signRadioButton.setSelected(true);
        signRadioButton.setText("Sign license");
        signRadioButton.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                signRadioClicked(evt);
            }
        });

        buttonGroup.add(validateRadioButton);
        validateRadioButton.setText("Validate license");
        validateRadioButton.addMouseListener(new java.awt.event.MouseAdapter() {
            public void mouseClicked(java.awt.event.MouseEvent evt) {
                validateRadioClicked(evt);
            }
        });

        javax.swing.GroupLayout jPanel2Layout = new javax.swing.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(validateRadioButton)
                    .addComponent(signRadioButton)))
        );
        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(signRadioButton)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(validateRadioButton)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jPanel1, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addComponent(jPanel2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(97, 97, 97)
                        .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                            .addComponent(closeButton, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(actionButton, javax.swing.GroupLayout.DEFAULT_SIZE, 155, Short.MAX_VALUE))))
                .addContainerGap())
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jPanel2, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addComponent(actionButton)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(closeButton)))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(jPanel1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void actionButtonClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_actionButtonClicked
        try {
            // TODO add your handling code here:
            if (signRadioButton.isSelected()) {
                licenseFile = jTextField.getText();
                signedLicenseFile = jTextField2.getText();
                publicKeyFile = jTextField3.getText();
                privateKeyFile = jTextField4.getText();

                if (licenseFile.equals("")) {
                    JOptionPane.showMessageDialog(rootPane, "Add license file", "License file is missing", JOptionPane.WARNING_MESSAGE);
                } else if (publicKeyFile.equals("")) {
                    JOptionPane.showMessageDialog(rootPane, "Add public key file", "Public key file is missing", JOptionPane.WARNING_MESSAGE);
                } else if (privateKeyFile.equals("")) {
                    JOptionPane.showMessageDialog(rootPane, "Add private key file", "Private key file is missing", JOptionPane.WARNING_MESSAGE);
                } else if (signedLicenseFile.equals("")) {
                    JOptionPane.showMessageDialog(rootPane, "Add signed license file", "Signed license file is missing", JOptionPane.WARNING_MESSAGE);
                } else {
                    new SignatureCreator().signLicense(licenseFile, publicKeyFile, privateKeyFile, signedLicenseFile);
                    JOptionPane.showMessageDialog(rootPane, "License is signed successfully");
                }
            } else {
                signedLicenseFile = jTextField.getText();
                publicKeyFile = jTextField2.getText();

                if (signedLicenseFile.equals("")) {
                    JOptionPane.showMessageDialog(rootPane, "Add signed license file", "Signed license file is missing", JOptionPane.WARNING_MESSAGE);
                } else if (publicKeyFile.equals("")) {
                    JOptionPane.showMessageDialog(rootPane, "Add public key file", "Public key file is missing", JOptionPane.WARNING_MESSAGE);
                } else {
                    if (new SignatureValidator().verifyLicense(publicKeyFile, signedLicenseFile)) {
                        JOptionPane.showMessageDialog(rootPane, "License is valid", "Result", JOptionPane.INFORMATION_MESSAGE);
                    } else {
                        JOptionPane.showMessageDialog(rootPane, "License is not valid", "Result", JOptionPane.INFORMATION_MESSAGE);
                    }
                }
            }
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(rootPane, ex.getMessage(), "Application error", JOptionPane.ERROR_MESSAGE);
        }
}//GEN-LAST:event_actionButtonClicked

    private void closeClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_closeClicked
        // TODO add your handling code here:
        System.exit(0);
}//GEN-LAST:event_closeClicked

    private void browseFile(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_browseFile
        // TODO add your handling code here:

        JFileChooser fileChooser = new JFileChooser();

        File file;

        if (jTextField.getText() != null && (file = new File(jTextField.getText())).exists()) {
            fileChooser.setCurrentDirectory(file);
        } else if (lastSelectedFile != null) {
            fileChooser.setCurrentDirectory(lastSelectedFile);
        }

        if (signRadioButton.isSelected()) {
            fileChooser.setDialogTitle("Select license file");
            fileChooser.setMultiSelectionEnabled(false);
            fileChooser.setFileFilter(new FileNameExtensionFilter("*.txt", "txt"));
        } else {
            fileChooser.setDialogTitle("Select signed license file");
            fileChooser.setMultiSelectionEnabled(false);
            fileChooser.setFileFilter(new FileNameExtensionFilter("*.lic", "lic"));
        }

        int returnVal = fileChooser.showOpenDialog(this);

        if (returnVal == JFileChooser.APPROVE_OPTION) {
            jTextField.setText(fileChooser.getSelectedFile().getAbsolutePath());
            lastSelectedFile = fileChooser.getCurrentDirectory();
        }
}//GEN-LAST:event_browseFile

    private void browseFile2(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_browseFile2
        // TODO add your handling code here:

        JFileChooser fileChooser = new JFileChooser();

        File file;

        if (jTextField2.getText() != null && (file = new File(jTextField2.getText())).exists()) {
            fileChooser.setCurrentDirectory(file);
        } else if (lastSelectedFile != null) {
            fileChooser.setCurrentDirectory(lastSelectedFile);
        }

        if (signRadioButton.isSelected()) {
            fileChooser.setDialogTitle("Select signed license file");
            fileChooser.setMultiSelectionEnabled(false);
            fileChooser.setFileFilter(new FileNameExtensionFilter("*.lic", "lic"));
        } else {
            fileChooser.setDialogTitle("Select public key file");
            fileChooser.setMultiSelectionEnabled(false);
            fileChooser.setFileFilter(new FileNameExtensionFilter("*.pbk", "pbk"));
        }

        int returnVal = fileChooser.showOpenDialog(this);

        if (returnVal == JFileChooser.APPROVE_OPTION) {
            jTextField2.setText(fileChooser.getSelectedFile().getAbsolutePath());
            lastSelectedFile = fileChooser.getCurrentDirectory();
        }

}//GEN-LAST:event_browseFile2

    private void browseFile3(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_browseFile3
        // TODO add your handling code here:

        JFileChooser fileChooser = new JFileChooser();

        File file;

        if (jTextField3.getText() != null && (file = new File(jTextField3.getText())).exists()) {
            fileChooser.setCurrentDirectory(file);
        } else if (lastSelectedFile != null) {
            fileChooser.setCurrentDirectory(lastSelectedFile);
        }

        fileChooser.setDialogTitle("Select public key file");
        fileChooser.setMultiSelectionEnabled(false);
        fileChooser.setFileFilter(new FileNameExtensionFilter("*.pbk", "pbk"));

        int returnVal = fileChooser.showOpenDialog(this);

        if (returnVal == JFileChooser.APPROVE_OPTION) {
            jTextField3.setText(fileChooser.getSelectedFile().getAbsolutePath());
            lastSelectedFile = fileChooser.getCurrentDirectory();
        }

}//GEN-LAST:event_browseFile3

    private void browseFile4(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_browseFile4
        // TODO add your handling code here:

        JFileChooser fileChooser = new JFileChooser();

        File file;

        if (jTextField4.getText() != null && (file = new File(jTextField4.getText())).exists()) {
            fileChooser.setCurrentDirectory(file);
        } else if (lastSelectedFile != null) {
            fileChooser.setCurrentDirectory(lastSelectedFile);
        }

        fileChooser.setDialogTitle("Select private key file");
        fileChooser.setMultiSelectionEnabled(false);
        fileChooser.setFileFilter(new FileNameExtensionFilter("*.prk", "prk"));

        int returnVal = fileChooser.showOpenDialog(this);

        if (returnVal == JFileChooser.APPROVE_OPTION) {
            jTextField4.setText(fileChooser.getSelectedFile().getAbsolutePath());
            lastSelectedFile = fileChooser.getCurrentDirectory();
        }

}//GEN-LAST:event_browseFile4

    private void signRadioClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_signRadioClicked
        // TODO add your handling code here:
        if (signRadioButton.isSelected()) {
            jLabel.setText("License file:");
            jLabel2.setText("Signed license file:");

            jLabel3.setVisible(true);
            jLabel4.setVisible(true);

            jTextField3.setVisible(true);
            jTextField4.setVisible(true);

            browseButton3.setVisible(true);
            browseButton4.setVisible(true);

            actionButton.setText("Sign license");

            signedLicenseFile = jTextField.getText();
            publicKeyFile = jTextField2.getText();

            jTextField.setText(licenseFile);
            jTextField2.setText(signedLicenseFile);
            jTextField3.setText(publicKeyFile);
            jTextField4.setText(privateKeyFile);
        }
    }//GEN-LAST:event_signRadioClicked

    private void validateRadioClicked(java.awt.event.MouseEvent evt) {//GEN-FIRST:event_validateRadioClicked
        // TODO add your handling code here:
        if (validateRadioButton.isSelected()) {
            jLabel.setText("Signed license file:");
            jLabel2.setText("Public key file:");

            jLabel3.setVisible(false);
            jLabel4.setVisible(false);

            jTextField3.setVisible(false);
            jTextField4.setVisible(false);

            browseButton3.setVisible(false);
            browseButton4.setVisible(false);

            actionButton.setText("Validate license");

            licenseFile = jTextField.getText();
            signedLicenseFile = jTextField2.getText();
            publicKeyFile = jTextField3.getText();
            privateKeyFile = jTextField4.getText();

            jTextField.setText(signedLicenseFile);
            jTextField2.setText(publicKeyFile);
        }
    }//GEN-LAST:event_validateRadioClicked

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton actionButton;
    private javax.swing.JButton browseButton;
    private javax.swing.JButton browseButton2;
    private javax.swing.JButton browseButton3;
    private javax.swing.JButton browseButton4;
    private javax.swing.ButtonGroup buttonGroup;
    private javax.swing.JButton closeButton;
    private javax.swing.JLabel jLabel;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JTextField jTextField;
    private javax.swing.JTextField jTextField2;
    private javax.swing.JTextField jTextField3;
    private javax.swing.JTextField jTextField4;
    private javax.swing.JRadioButton signRadioButton;
    private javax.swing.JRadioButton validateRadioButton;
    // End of variables declaration//GEN-END:variables
    private String licenseFile = "";
    private String signedLicenseFile = "";
    private String publicKeyFile = "";
    private String privateKeyFile = "";
    private File lastSelectedFile;
}
