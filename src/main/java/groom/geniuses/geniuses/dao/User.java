package groom.geniuses.geniuses.dao;

public class User {
    private String user_id;
    private String user_pw;
    private String user_name;
    private String user_profile;

    public User(String user_id, String user_pw, String user_name, String user_profile) {
        this.user_id = user_id;
        this.user_pw = user_pw;
        this.user_name = user_name;
        this.user_profile = user_profile;
    }

    // Getters and Setters
    public String getUser_id() {
        return user_id;
    }

    public String getUser_pw() {
        return user_pw;
    }

    public String getUser_name() {
        return user_name;
    }

    public String getUser_profile() {
        return user_profile;
    }
}
