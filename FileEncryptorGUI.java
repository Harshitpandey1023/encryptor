import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class FileEncryptorGUI extends JFrame implements ActionListener {

    private JButton chooseFileButton;
    private JButton encryptButton;
    private JButton decryptButton;
    private JLabel inputFileLabel;
    private JLabel outputFileLabel;
    private JFileChooser fileChooser;
    private File inputFile;
    private File encryptedFile;
    private File decryptedFile;

    private static final String ENCRYPTION_ALGORITHM = "AES";
    private static final int BUFFER_SIZE = 8192;

    public FileEncryptorGUI() {
        super("File Encryptor");
        setSize(400, 200);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        chooseFileButton = new JButton("Choose File");
        encryptButton = new JButton("Encrypt");
        decryptButton = new JButton("Decrypt");

        chooseFileButton.addActionListener(this);
        encryptButton.addActionListener(this);
        decryptButton.addActionListener(this);

        inputFileLabel = new JLabel("No file selected");
        outputFileLabel = new JLabel("");

        JPanel panel = new JPanel(new GridLayout(0, 1));
        panel.add(chooseFileButton);
        panel.add(inputFileLabel);
        panel.add(encryptButton);
        panel.add(decryptButton);
        panel.add(outputFileLabel);

        add(panel);

        fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Choose a file");

        setVisible(true);
    }

    public void actionPerformed(ActionEvent e) {
        if (e.getSource() == chooseFileButton) {
            int returnValue = fileChooser.showOpenDialog(this);
            if (returnValue == JFileChooser.APPROVE_OPTION) {
                inputFile = fileChooser.getSelectedFile();
                inputFileLabel.setText(inputFile.getName());
            }
        } else if (e.getSource() == encryptButton) {
            if (inputFile == null) {
                JOptionPane.showMessageDialog(this, "Please choose a file to encrypt.");
            } else {
                String password = askForPassword();
                if (password == null) {
                    return; 
                }

                try (FileInputStream inputStream = new FileInputStream(inputFile);
                     FileOutputStream outputStream = new FileOutputStream("encrypted.txt")) {

                    SecretKeySpec secretKeySpec = generateKey(password);

                    Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
                    cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

                    byte[] inputBuffer = new byte[BUFFER_SIZE];
                    int bytesRead;
                    while ((bytesRead = inputStream.read(inputBuffer)) != -1) {
                        byte[] outputBuffer = cipher.update(inputBuffer, 0, bytesRead);
                        outputStream.write(outputBuffer);
                    }
                    byte[] outputBuffer = cipher.doFinal();
                    outputStream.write(outputBuffer);

                    encryptedFile = new File("encrypted.txt");
                    outputFileLabel.setText("Encrypted file: " + encryptedFile.getName());
                } catch (FileNotFoundException ex) {
                    JOptionPane.showMessageDialog(this, "Error encrypting file: File not found.");
                } catch (IOException ex) {
                    JOptionPane.showMessageDialog(this, "Error encrypting file: " + ex.getMessage());
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(this, "Error encrypting file: " + ex.getMessage());
                }
            }
        } else if (e.getSource() == decryptButton) {
            if (encryptedFile == null) {
                JOptionPane.showMessageDialog(this, "Please encrypt a file first.");
            } else {
                String password = askForPassword();
                if (password == null) {
                    return; 
                }

                try (FileInputStream inputStream = new FileInputStream(encryptedFile);
                     FileOutputStream outputStream = new FileOutputStream("decrypted.txt")) {

                    SecretKeySpec secretKeySpec = generateKey(password);

                    Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
                    cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

                    byte[] inputBuffer = new byte[BUFFER_SIZE];
                    int bytesRead;
                    while ((bytesRead = inputStream.read(inputBuffer)) != -1) {
                        byte[] outputBuffer = cipher.update(inputBuffer, 0, bytesRead);
                        outputStream.write(outputBuffer);
                    }
                    byte[] outputBuffer = cipher.doFinal();
                    outputStream.write(outputBuffer);

                    decryptedFile = new File("decrypted.txt");
                    outputFileLabel.setText("Decrypted file: " + decryptedFile.getName());
                } catch (FileNotFoundException ex) {
                    JOptionPane.showMessageDialog(this, "Error decrypting file: File not found.");
                } catch (IOException ex) {
                    JOptionPane.showMessageDialog(this, "Error decrypting file: " + ex.getMessage());
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(this, "Error decrypting file: " + ex.getMessage());
                }
            }
        }
    }

    private String askForPassword() {
        JPasswordField passwordField = new JPasswordField();
        int option = JOptionPane.showConfirmDialog(this, passwordField, "Enter Password", JOptionPane.OK_CANCEL_OPTION);
        if (option == JOptionPane.OK_OPTION) {
            return new String(passwordField.getPassword());
        }
        return null;
    }

    private SecretKeySpec generateKey(String password) throws NoSuchAlgorithmException {
        byte[] keyBytes = generateKeyBytes(password);
        SecretKeySpec secretKeySpec = new SecretKeySpec(keyBytes, ENCRYPTION_ALGORITHM);
        return secretKeySpec;
    }

    private byte[] generateKeyBytes(String password) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = digest.digest(password.getBytes(StandardCharsets.UTF_8));
        return Arrays.copyOf(keyBytes, 16); 
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            new FileEncryptorGUI();
        });
    }
}

