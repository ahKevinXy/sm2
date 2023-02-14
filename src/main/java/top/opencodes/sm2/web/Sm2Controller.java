package top.opencodes.sm2.web;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import org.springframework.web.bind.annotation.*;
import lombok.extern.slf4j.Slf4j;
import top.opencodes.sm2.dto.SignParam;
import top.opencodes.sm2.util.DCCryptor;
import top.opencodes.sm2.util.DCHelper;
import top.opencodes.sm2.util.Sm2KeyHelp;

import java.util.Base64;
import java.util.Map;
import java.nio.charset.StandardCharsets;
import java.util.Random;


@Slf4j
@RestController
public class Sm2Controller {
    private static Base64.Encoder encoder = Base64.getEncoder();
    private static Base64.Decoder decoder = Base64.getDecoder();
    @GetMapping("/api/demo/encrypt")
    public String encrypt(@RequestParam String SOURCES,
                          @RequestParam String SM2_PUBKEY_TEST
    ) {
        Map<String, byte[]> keypair = Sm2KeyHelp.CMBSM2KeyGen();
        byte[] publickey = keypair.get("publickey");
        byte[] privatekey = keypair.get("privatekey");
        log.info("用户公钥: " + Base64.getEncoder().encodeToString(publickey));
        log.info("用户私钥: " + Base64.getEncoder().encodeToString(privatekey));

        try {
            String sm4key = Sm2KeyHelp.genRandomString(new Random(), SOURCES, 16);
            log.info("用户对称密钥: " + sm4key);
            String sm2EnKey = Base64.getEncoder().encodeToString(Sm2KeyHelp.CMBSM2Encrypt(Base64.getDecoder().decode(SM2_PUBKEY_TEST), sm4key.getBytes(StandardCharsets.UTF_8)));
            log.info("加密后用户对称密钥: " + sm2EnKey);
            return sm2EnKey;
        } catch (Exception e) {
            e.printStackTrace();

        }
        return null;
    }

    @PostMapping("/api/demo/decrypt")
    public String decrypt() {
        // TODO
        return null;
    }
    @GetMapping("/")
    public String Home(){

        return "这是首页";
    }

//    @RequestMapping(value = "api/sign",method = RequestMethod.POST,consumes = "application/json")

    @PostMapping("api/sign")
    public String Sign(@RequestBody SignParam signParam) throws Exception {

//        String source = DCHelper.serialJsonOrdered(jObject);

//        JsonObject obj = new JsonObject();
//        Gson gson = new Gson();
//        gson.fromJson(signParam.getSign_content(),obj.getClass());
//
//        String source = DCHelper.serialJsonOrdered(obj);

        byte[] signature1=  DCCryptor.CMBSM2SignWithSM3(getID_IV(signParam.getUser_id()),decoder.decode(signParam.getPrivate_key()),signParam.getSign_content().getBytes(StandardCharsets.UTF_8));
        System.out.println("加密用户ID："+new String(getID_IV(signParam.getUser_id())));
        System.out.println("加密私钥:"+signParam.getPrivate_key());
        System.out.println("加密内容:"+signParam.getSign_content());
        System.out.println("加密结果:"+new String(encoder.encode(signature1)));
        return new String(encoder.encode(signature1));
    }

    private static byte[] getID_IV(String uid) {
       ; // 请替换为实际的用户UID
        String userid = uid + "0000000000000000";
        return userid.substring(0, 16).getBytes();
    }
}
