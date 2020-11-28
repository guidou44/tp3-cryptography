package ex2.protocols.base;

/*
 * Interface qui représente un client pour un protocole donnée. L'idée est d'utiliser le design pattern 'Observer'.
 * Par exemple, un client reçoit comme observeur son serveur et un serveur reçoit comme observeur son client.
 * Cependant, puisque que l'observeur est câché derrière un interface, l'objet observé ne sait pas si c'est réellement le client ou bien
 * un intrus...
 * */
public interface IProtocolClient<T extends IProtocolStep> {

    void acceptClientSide(T lastStep, T nextStep, String message) throws Exception;

}
