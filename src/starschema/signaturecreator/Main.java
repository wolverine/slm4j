/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package starschema.signaturecreator;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;

/**
 *
 * @author User
 */
public class Main {

    private static final String OPTION_SIGN = "sign";
    private static final String OPTION_VERIFY = "verify";
    private static final String PARAMETER_LICENSE = "-license";
    private static final String PARAMETER_PUBLIC = "-public";
    private static final String PARAMETER_PRIVATE = "-private";
    private static final String PARAMETER_SIGNATURE = "-sign";

    public static void main(String[] args) {
        try {
            executeApplication(args);
        } catch (Exception ex) {
            ex.printStackTrace();
            System.out.println(ex.getMessage());
        }
    }

    public static boolean executeApplication(String[] arguments) throws LicenseGeneratorException {
        HashMap parameters = new HashMap();
        Set parameterSet;
        Set parameterSetSign = new HashSet();
        Set parameterSetVerify = new HashSet();
        String processType;
        String usageString[];

        try {
            parameterSetSign.add(PARAMETER_LICENSE);
            parameterSetSign.add(PARAMETER_PUBLIC);
            parameterSetSign.add(PARAMETER_PRIVATE);
            parameterSetSign.add(PARAMETER_SIGNATURE);

            parameterSetVerify.add(PARAMETER_PUBLIC);
            parameterSetVerify.add(PARAMETER_SIGNATURE);

            usageString = new String[9];

            usageString[0] = "Usage: java -jar LicenseGenerator.jar option parameters";
            usageString[1] = " option:";
            usageString[2] = "  sign - Write a signature in in the signature file after the content of the source file.";
            usageString[3] = "  verify - Verifies a signature file based on the key file.";
            usageString[4] = " parameters:";
            usageString[5] = "  -license license_file - Source file to add signature.";
            usageString[6] = "  -public public_key_file - Public key file. If sign then the public key will be written in this file. If verify then the verification will based on the public key stored in this file.";
            usageString[7] = "  -private private_key_file - Private key file. Available only for sign. The private key will be stored in this file.";
            usageString[8] = "  -signed signature_file - The signed license file. It is the output file of the sign and the input of the verification.";

            if (arguments.length == 0) {
                System.out.println(usageString[0]);
                return false;
            }

            if (arguments.length % 2 != 1) {
                System.out.println("Wrong number of arguments");
                return false;
            }

            if (arguments[0].toLowerCase().equals(OPTION_SIGN)) {
                parameterSet = parameterSetSign;
            } else if (arguments[0].toLowerCase().equals(OPTION_VERIFY)) {
                parameterSet = parameterSetVerify;
            } else {
                System.out.println("Invalid option - Choose \"sign\", \"verify\"");
                return false;
            }

            for (int i = 1; i < arguments.length; i++) {
                if (i % 2 == 1 && (!parameterSet.contains(arguments[i]) || parameters.containsKey(arguments[i]))) {
                    System.out.println("Invalid or duplicated parameter \"" + arguments[i] + "\"");
                    return false;
                }
                if (i % 2 == 0) {
                    parameters.put(arguments[i - 1], arguments[i]);
                }
            }

            if (parameterSet.size() != parameters.size()) {
                System.out.println("All of the parameters must be set " + parameterSet);
                return false;
            }

            if (arguments[0].equals(OPTION_SIGN)) {
                new SignatureCreator().signLicense((String) parameters.get(PARAMETER_LICENSE), (String) parameters.get(PARAMETER_PUBLIC), (String) parameters.get(PARAMETER_PRIVATE), (String) parameters.get(PARAMETER_SIGNATURE));
            } else {
                if (new SignatureValidator().verifyLicense((String) parameters.get(PARAMETER_PUBLIC), (String) parameters.get(PARAMETER_SIGNATURE))) {
                    System.out.println("License is valid");

                } else {
                    System.out.println("License is not valid");
                    
                }
            }

            return true;
        } catch (Exception ex) {
            throw new LicenseGeneratorException("Error in signature generation or verification ( " + ex.getMessage() + " )");
        }
    }
}