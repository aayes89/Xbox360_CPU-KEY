package x360cpukeybforce;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 *
 * @author Slam
 */
public class X360CpuKeyBForce {

    public static void main(String[] args) {
        RSAKeyGenerator rsakg = new RSAKeyGenerator();
        rsakg.genRSAKey();

        List<String> salts = getSalts();
        /*
        //Used for brute force method
        int count = 100;                         // cpu-keys to generate
        List<String> keys = generateKeys(count); // cpu-key list
        for (String key : keys) {
            System.out.println(key);
        }
         //String keyBits = convertToBinary(key);  // change to bits array

        // prints ECC and UID bits 
        System.out.println("ECC Bits: " + keyBits.substring(keyBits.length() - 26));
        System.out.println("UID Bits: " + keyBits.substring(0, keyBits.length() - 26));
         */
         // Print the CPU-KEY with Salt
        String key = cpuKeyGen();        // generate a CPU-KEY
        for (String salt : salts) {
            String keyWSalt = XeCryptCpuKeyGen(salt);
            System.out.println("CPU-KEY with Salt: " + keyWSalt.toUpperCase());
        }

        // Print the CPU-KEY
        System.out.println("CPU-KEY          : " + key.toUpperCase());
    }

    // CPU-KEY generator
    private static String cpuKeyGen() {
        Random random = new Random();
        StringBuilder keyBuilder = new StringBuilder();
        for (int i = 0; i < 32; i++) {
            keyBuilder.append(Integer.toHexString(random.nextInt(16)));
        }
        return keyBuilder.toString();
    }

    // CPU-KEY generator with salt
    private static String XeCryptCpuKeyGen(String salt) {
        // Generar una clave aleatoria de 16 bytes
        byte[] randomBytes = new byte[16];
        new SecureRandom().nextBytes(randomBytes);

        // Agregar el salt a la clave generada
        byte[] keyWithSalt = new byte[randomBytes.length + salt.length()];
        System.arraycopy(randomBytes, 0, keyWithSalt, 0, randomBytes.length);
        System.arraycopy(salt.getBytes(), 0, keyWithSalt, randomBytes.length, salt.length());

        // Aplicar un algoritmo de hash (SHA-256) a la clave con salt
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(keyWithSalt);

            // Convertir el hash a una cadena hexadecimal
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString().substring(0, 32); // Tomar solo los primeros 32 caracteres
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    private static String XeCryptCpuKeyGen00(String salt) {
        // Aquí iría la implementación de la función XeCryptCpuKeyGen() con salt en Java
        // Por ejemplo, podrías generar una clave aleatoria y concatenarla con el salt, y luego aplicar algún algoritmo de hash
        Random random = new Random();
        StringBuilder keyBuilder = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            keyBuilder.append(Integer.toHexString(random.nextInt(16)));
        }
        String key = keyBuilder.toString();

        // Agrega el salt a la clave generada
        key += salt;

        // Aplica algún algoritmo de hash, por ejemplo, SHA-256
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(key.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            System.err.println(e.getMessage());
            return null;
        }
    }

    // fetch Salt from external file 
    private static List<String> getSalts() {
        File saltsFile = new File(X360CpuKeyBForce.class.getResource("salts.txt").getFile());
        List<String> salts = new ArrayList<>();
        BufferedReader br;
        try {
            br = new BufferedReader(new FileReader(saltsFile));
            String line;
            while ((line = br.readLine()) != null) {
                salts.add(line);
            }
        } catch (IOException ex) {
            System.err.println(ex.getMessage());
        }
        return salts;
    }
     //Brute Force mode
    /**
         * Demostración de ataque por fuerza bruta a AES ECB (versión
         * simplificada)
         *
         * @param textoCifrado
         * @param textoPlanoConocido
         * @param claveInicial Suposición inicial cercana a la real para
         * demostración
         */
        // Debería recibir el texto plano esperado como parámetro
        public static void fuerzaBrutaAES_ECB(byte[] textoCifrado, byte[] textoPlanoConocido, byte[] claveInicial) {
            // Implementación didáctica con clave de ejemplo cercana
            byte[] clavePrueba = Arrays.copyOf(claveInicial, claveInicial.length);
            //clavePrueba[clavePrueba.length - 1] = (byte) (clavePrueba[clavePrueba.length - 1] - 10);
            // Simulación de intento de adivinanza incrementando valores
            for (int i = 0; i < Long.MAX_VALUE; i++) { // Límite para demostración
                System.out.println("Intento: " + (i + 1) + " de clave: " + Utils.bytesToHex(clavePrueba));
                try {
                    SecretKeySpec clave = new SecretKeySpec(clavePrueba, "AES");
                    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                    cipher.init(Cipher.DECRYPT_MODE, clave);
                    byte[] descifrado = cipher.doFinal(textoCifrado);

                    if (Arrays.equals(descifrado, textoPlanoConocido)) {
                        System.out.println("¡Clave encontrada!\n\t" + Utils.bytesToHex(clavePrueba) + "\n");
                        System.out.println("Texto descifrado: " + new String(descifrado));
                        return;
                    }
                } catch (Exception e) {
                    /* Ignorar errores */ }

                // Incremento secuencial
                if (!Utils.incrementKey(clavePrueba)) {
                    // Si ya se recorrieron todas las claves, salimos
                    break;
                }
            }
            System.out.println("Ataque didáctico finalizado sin éxito (esperado)");
        }
    
    public static boolean incrementKey(byte[] key) {
            for (int i = key.length - 1; i >= 0; i--) {
                int currentByte = key[i] & 0xFF; // Convertir a entero sin signo
                if (currentByte != 0xFF) {
                    key[i] = (byte) (currentByte + 1);
                    return true;
                }
                key[i] = 0;
            }
            return false;
        }
    /* 
   
    private static List<String> generateKeys(int count) {
        List<String> list = new ArrayList<>();
        Random random = new Random();

        for (int i = 0; i < count; i++) {
            StringBuilder keyBuilder = new StringBuilder();
            for (int j = 0; j < 8; j++) { // generate 8 hexadecimals character por cada clave de 32 bits
                int num = random.nextInt(16); // generate random number between 0 and 15 (f - hex)
                char hexChar = (char) (num < 10 ? num + '0' : num - 10 + 'a'); // converts to hex
                keyBuilder.append(hexChar);
            }
            list.add(keyBuilder.toString());
        }

        return list;
    }
    // Hex to bits
    private static String convertToBinary(String hexString) {
        StringBuilder binaryString = new StringBuilder();
        for (int i = 0; i < hexString.length(); i++) {
            String binary = Integer.toBinaryString(Integer.parseInt(hexString.substring(i, i + 1), 16));
            binaryString.append("0000".substring(binary.length())).append(binary);
        }
        return binaryString.toString();
    }*/
}
