package top.opencodes.sm2.web;

import org.springframework.web.bind.annotation.*;
import lombok.extern.slf4j.Slf4j;
import top.opencodes.sm2.dto.SignParam;
import top.opencodes.sm2.util.DCCryptor;
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
         System.out.println(signParam.getSign_content());
         System.out.println(signParam.getPrivate_key());
         System.out.println(signParam.getUser_id());
        byte[] signature1=  DCCryptor.CMBSM2SignWithSM3(signParam.getUser_id().getBytes(),signParam.getPrivate_key().getBytes(),signParam.getSign_content().getBytes(StandardCharsets.UTF_8));

        return new String(encoder.encode(signature1));
    }
}
