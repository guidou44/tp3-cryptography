package ex2.protocols.WebAuthn;

import ex2.cryptography.Rsa1024Cipher;
import ex2.domain.Credential;
import ex2.protocols.base.Protocol;
import ex2.utils.FileSystemUtil;

import java.io.IOException;
import java.util.List;

/*
* Classe qui abstract qui contient certaine variables et constantes que le client et le serveur de WebAuthn ont en commun.
* À noter qu'ils ne partagent pas les mêmes instances de ces variables, sauf pour les constantes.
* */
public abstract class WebAuthn extends Protocol {

    protected static  final String BASE_DIRECTORY = "WebAuthn/";

    protected final Rsa1024Cipher rsa = new Rsa1024Cipher();

    protected String _currentUser;
    protected String _currentDomain;
    protected int _sessionId = 0;
}
