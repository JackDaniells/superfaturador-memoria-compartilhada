package br.ufsc.ine5611;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;


public class App {

    private static int sizeLength = 4;
    private static int hashLength = 32;

    public static void main(String[] args) throws IOException{
        
        try {
            
            /*************************************************
            * 
            *      Pega os parametros passados como argumento
            * 
            *************************************************/
            
            //inicia o proccessBuilder com o path do signer
            ProcessBuilder builder = new ProcessBuilder(args[0]);
            
            //cria o pipe in e o pipe out
            builder.redirectInput(ProcessBuilder.Redirect.PIPE);
            builder.redirectOutput(ProcessBuilder.Redirect.PIPE);
            
            //arquivo a ser superfaturado
            File file = new File(args[1]);
            
            //inicializa os buffer onde o arquivo vai ser lido
            byte[] buffer = new byte[(int) file.length()];    
            
            //le o arquivo recebido
            FileInputStream fs = new FileInputStream(file);
            //aponta pro buffer onde o arquivo vai ser lido
            fs.read(buffer);

            /*************************************************
            * 
            *   cria o pacote e inicializa a memoria mapeada
            * 
            *************************************************/
            
            
            long packSize = sizeLength + file.length() + hashLength;
            
            //cria um arquivo vazio temporariamente
            Path path = Files.createTempFile(null, null);
            
            //inicializa o fileChannel com o arquivo temporario
            FileChannel ch = FileChannel.open(
                    path, 
                    StandardOpenOption.READ, 
                    StandardOpenOption.WRITE
            );
            
            //inicializa o MappedByteBuffer com o tamanho do pacote
            MappedByteBuffer mb = ch.map(FileChannel.MapMode.READ_WRITE, 0, packSize);
            
            //finaliza o FileChannel
            ch.close();
            
            /*************************************************
            * 
            *            Popula a memoria mapeada
            * 
            *************************************************/

            //posiciona o MappedByteBuffer
            mb.position(0);
            //escreve o tamanho do arquivo na posição 0
            mb.putInt((int)file.length());

            //escreve o payload na memoria mapeada
            for (int i = 0; i < buffer.length; i++){     
                //posiciona o MappedByteBuffer
                mb.position(sizeLength + i);
                //escreve o buffer[i] na posição atual
                mb.put(buffer[i]);
            }
            
            /************************************************
             * 
             *  Inicia o signer e espera o processo terminar
             * 
             ************************************************/
            
            //cria o processo
            Process process = builder.start();
            
            //usa a classe SignerClient 
            SignerClient signerClient = new SignerClient(process.getOutputStream(), process.getInputStream());
            signerClient.sign(path.toFile());
                      
            //espera pelo termino do processo
            process.waitFor();
            
            //finaliza o signerClient
            signerClient.end();
            
            /************************************************
             * 
             *         Pega o hash da memoria mapeada
             * 
            *************************************************/
            
            //inicia os bytes correspondentes ao hash
            byte[] signature = new byte[hashLength];

            //pega o hash da memoria mapeada
            for (int i = 0; i < signature.length; i++) {
                long position = sizeLength + file.length() + i;
                signature[i] = mb.get((int)position);
            }

            //transforma signature numa string base 64 e a imprime
            System.out.println(Base64.getEncoder().encodeToString(signature));
            
            /************************************************
             * 
             *               compara os hash
             * 
             ************************************************/
            
            
            //pega SHA-256 sem superfaturamento.
            byte[] expectedSignature = getExpectedSignature(file);

            //compara o hash lido da memória mapeada com o hash calculado sem superfaturamento
            System.out.println(Arrays.equals(expectedSignature, signature)); 
           
            
        //exception
        } catch (SignerException | InterruptedException ex) {
            //imprime a exception
           System.err.println(ex.getMessage());
        }
    }
    
    
    //retorna o SHA-256 sem superfaturamento.
    private static byte[] getExpectedSignature(File file) throws IOException {
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Unexpected exception", e);
        }
        try (FileInputStream in = new FileInputStream(file)) {
            while (in.available() > 0) {
                md.update((byte) in.read());
            }
        }
        return md.digest();
    }

}
