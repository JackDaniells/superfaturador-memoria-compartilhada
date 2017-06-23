package br.ufsc.ine5611;

import org.apache.commons.io.output.CloseShieldOutputStream;

import java.io.*;
import java.util.Scanner;

public class SignerClient {
    private Scanner scanner;
    private PrintStream ps;

    public SignerClient(OutputStream outputStream, InputStream inputStream) {
        scanner = new Scanner(inputStream);
        try {
            ps = new PrintStream(new CloseShieldOutputStream(outputStream), true, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    public void sign(File mappedFile) throws SignerException {
        ps.printf("SIGN %s\n", mappedFile.getAbsolutePath());
        while (scanner.hasNextLine()) {
            String line = scanner.nextLine();
            if (line.equals("OK SIGN"))
                break;
            if (line.equals("ERROR BEGIN SIGN")) {
                StringBuilder errorMessage = new StringBuilder();
                while (scanner.hasNextLine()) {
                    String errorLine = scanner.nextLine();
                    if (errorLine.equals("ERROR END SIGN"))
                        break;
                    errorMessage.append(errorLine).append("\n");
                }
                throw new SignerException(errorMessage.toString());
            }
        }
    }

    public void end() {
        ps.printf("END\n");
    }
}
