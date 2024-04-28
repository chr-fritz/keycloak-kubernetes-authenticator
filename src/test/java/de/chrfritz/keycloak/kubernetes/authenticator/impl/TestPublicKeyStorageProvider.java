package de.chrfritz.keycloak.kubernetes.authenticator.impl;

import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.PublicKeysWrapper;
import org.keycloak.keys.PublicKeyLoader;
import org.keycloak.keys.PublicKeyStorageProvider;

import java.util.List;
import java.util.Objects;
import java.util.function.Predicate;

/**
 * Mock implementation for the {@link PublicKeyStorageProvider}
 */
class TestPublicKeyStorageProvider implements PublicKeyStorageProvider {

    private final PublicKeysWrapper wrapper;

    public TestPublicKeyStorageProvider(KeyWrapper keyWrapper) {
        wrapper = new PublicKeysWrapper(List.of(keyWrapper));
    }

    private PublicKeysWrapper load(PublicKeyLoader loader) {
        return wrapper;
    }

    @Override
    public KeyWrapper getPublicKey(String modelKey, String kid, String algorithm, PublicKeyLoader loader) {
        return load(loader).getKeyByKidAndAlg(kid, algorithm);
    }

    @Override
    public KeyWrapper getFirstPublicKey(String modelKey, String algorithm, PublicKeyLoader loader) {
        return getFirstPublicKey(modelKey, k -> Objects.equals(algorithm, k.getAlgorithm()), loader);
    }

    @Override
    public KeyWrapper getFirstPublicKey(String modelKey, Predicate<KeyWrapper> predicate, PublicKeyLoader loader) {
        return load(loader).getKeyByPredicate(predicate);
    }

    @Override
    public List<KeyWrapper> getKeys(String modelKey, PublicKeyLoader loader) {
        return load(loader).getKeys();
    }

    @Override
    public boolean reloadKeys(String modelKey, PublicKeyLoader loader) {
        return false;
    }

    @Override
    public void close() {
        // no-op
    }
}
