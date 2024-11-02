package pl.mlodawski.security.pkcs11.model;

public enum DeviceState {
    READY,
    NOT_PRESENT,
    NOT_INITIALIZED,
    PIN_NOT_INITIALIZED,
    PIN_LOCKED,
    ERROR
}
