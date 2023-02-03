package top.opencodes.sm2.dto;



import  java.lang.String;

public class SignParam {

    private String sign_content;


    private String private_key;

    private String user_id;

    public String getSign_content() {
        return sign_content;
    }

    public void setSign_content(String sign_content) {
        this.sign_content = sign_content;
    }

    public String getPrivate_key() {
        return private_key;
    }

    public void setPrivate_key(String private_key) {
        this.private_key = private_key;
    }

    public String getUser_id() {
        return user_id;
    }

    public void setUser_id(String user_id) {
        this.user_id = user_id;
    }
}
