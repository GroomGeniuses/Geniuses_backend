package groom.geniuses.geniuses.jwt.oauth2;

public interface OAuth2UserInfo {
    String getProvider();
    String getProviderId();
    String getEmail();
    String getName();
    String getImage();
}