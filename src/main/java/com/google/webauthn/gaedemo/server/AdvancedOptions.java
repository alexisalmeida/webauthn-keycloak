package com.google.webauthn.gaedemo.server;

public class AdvancedOptions {

    private String conveyancePreference = "none";
    private String userVerification = "none";
    private String attachmentType = "none";

    private Boolean excludeCredentials = false;
    private Boolean preventReregistration = false;
    private Boolean requireResidentKey = false;

    String getAttachmentType() {
        return attachmentType;
    }

    public void setAttachmentType(String attachmentType) {
        this.attachmentType = attachmentType;
    }

    String getConveyancePreference() {
        return conveyancePreference;
    }

    public void setConveyancePreference(String conveyancePreference) {
        this.conveyancePreference = conveyancePreference;
    }

    String getUserVerification() {
        return userVerification;
    }

    public void setUserVerification(String userVerification) {
        this.userVerification = userVerification;
    }

    Boolean getExcludeCredentials() {
        return excludeCredentials;
    }

    public void setExcludeCredentials(Boolean excludeCredentials) {
        this.excludeCredentials = excludeCredentials;
    }

    public Boolean getPreventReregistration() {
        return preventReregistration;
    }

    public void setPreventReregistration(Boolean preventReregistration) {
        this.preventReregistration = preventReregistration;
    }

    Boolean getRequireResidentKey() {
        return requireResidentKey;
    }

    public void setRequireResidentKey(Boolean requireResidentKey) {
        this.requireResidentKey = requireResidentKey;
    }

}
