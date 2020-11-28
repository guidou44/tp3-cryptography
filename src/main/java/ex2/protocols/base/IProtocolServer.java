package ex2.protocols.base;

/*
* Interface qui représente un serveur pour un protocole donnée. L'idée est d'utiliser le design pattern 'Observer'.
* Par exemple, un client reçoit comme observeur son serveur et un serveur reçoit comme observeur son client.
* Cependant, puisque que l'observeur est câché derrière un interface, l'objet observé ne sait pas si c'est réellement le serveur ou bien
* un intrus...
* */
public interface IProtocolServer<T extends IProtocolStep> {
    void acceptServerSide(T lastStep, T nextStep, String message) throws Exception;
}
