package groom.geniuses.dto;

public class UserResponse {
    private String user_name;
    private String user_profile;

    public UserResponse(String user_name, String user_profile) {
        this.user_name = user_name;
        this.user_profile = user_profile;
    }

    // Getters
    public String getUser_name() {
        return user_name;
    }

    public String getUser_profile() {
        return user_profile;
    }
}
