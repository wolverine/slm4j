/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */

package starschema.signaturecreator;

/**
 *
 * @author User
 */
public class LicenseGeneratorException extends Exception {
    private String message;

    public LicenseGeneratorException(String message) {
        this.message = message;
    }

    public String getMessage() {
        return message;
    }
}
