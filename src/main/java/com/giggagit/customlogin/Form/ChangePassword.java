package com.giggagit.customlogin.Form;

import javax.validation.constraints.NotBlank;

/**
 * ChangePassword
 */
public class ChangePassword {

    @NotBlank
    private String currentPassword;
    
    @NotBlank
    private String newPassword;

    @NotBlank
    private String confirmNewPassword;

    public String getCurrentPassword() {
        return this.currentPassword;
    }

    public void setCurrentPassword(String currentPassword) {
        this.currentPassword = currentPassword;
    }

    public String getNewPassword() {
        return this.newPassword;
    }

    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }

    public String getConfirmNewPassword() {
        return this.confirmNewPassword;
    }

    public void setConfirmNewPassword(String confirmNewPassword) {
        this.confirmNewPassword = confirmNewPassword;
    }

}