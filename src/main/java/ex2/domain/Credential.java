package ex2.domain;

/*
* Classe qui encapsule des informations de credential pour WebAuthn: user, privateKey, domaine
* */
public class Credential {
    private String user;
    private String privateKey;
    private String domain;

    public Credential(String user, String privateKey, String domain) {
        this.user = user;
        this.privateKey = privateKey;
        this.domain = domain;
    }

    public String getUser() {
        return user;
    }

    public String getPrivateKey() {
        return privateKey;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    public String getDomain() {
        return domain;
    }

    @Override
    public String toString() {
        return domain + " " + user + " " + privateKey;
    }
}
