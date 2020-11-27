package ex2.protocols;

import ex2.protocols.base.Protocol;

public class WebAuthn extends Protocol {


    @Override
    protected String getPasswordHashFromAuthMessage(String message) {
        return null;
    }
}
