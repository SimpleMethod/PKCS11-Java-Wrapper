package pl.mlodawski.security.pkcs11.jna.structure;

import com.sun.jna.Memory;
import com.sun.jna.NativeLong;
import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import pl.mlodawski.security.pkcs11.jna.constants.AttributeType;
import pl.mlodawski.security.pkcs11.jna.constants.ObjectClass;

import java.nio.charset.StandardCharsets;

/**
 * PKCS#11 CK_ATTRIBUTE structure.
 * Represents an attribute type-value pair.
 * Based on OASIS PKCS#11 specification.
 */
@Structure.FieldOrder({"type", "pValue", "ulValueLen"})
public class Attribute extends Structure {

    /**
     * The attribute type (CKA_* value).
     */
    public NativeLong type;

    /**
     * Pointer to the attribute value.
     */
    public Pointer pValue;

    /**
     * Length of the value in bytes.
     */
    public NativeLong ulValueLen;

    public Attribute() {
        super();
        this.type = new NativeLong(0);
        this.pValue = null;
        this.ulValueLen = new NativeLong(0);
    }

    /**
     * Creates an attribute with the specified type (for querying value length).
     */
    public Attribute(long attributeType) {
        super();
        this.type = new NativeLong(attributeType);
        this.pValue = null;
        this.ulValueLen = new NativeLong(0);
    }

    /**
     * Creates an attribute with a byte array value.
     */
    public Attribute(long attributeType, byte[] value) {
        super();
        this.type = new NativeLong(attributeType);
        if (value != null && value.length > 0) {
            this.pValue = new Memory(value.length);
            this.pValue.write(0, value, 0, value.length);
            this.ulValueLen = new NativeLong(value.length);
        } else {
            this.pValue = null;
            this.ulValueLen = new NativeLong(0);
        }
    }

    /**
     * Creates an attribute with a NativeLong value.
     */
    public Attribute(long attributeType, NativeLong value) {
        super();
        this.type = new NativeLong(attributeType);
        this.pValue = new Memory(NativeLong.SIZE);
        if (NativeLong.SIZE == 8) {
            this.pValue.setLong(0, value.longValue());
        } else {
            this.pValue.setInt(0, value.intValue());
        }
        this.ulValueLen = new NativeLong(NativeLong.SIZE);
    }

    /**
     * Creates an attribute with a long value.
     */
    public Attribute(long attributeType, long value) {
        super();
        this.type = new NativeLong(attributeType);
        this.pValue = new Memory(NativeLong.SIZE);
        if (NativeLong.SIZE == 8) {
            this.pValue.setLong(0, value);
        } else {
            this.pValue.setInt(0, (int) value);
        }
        this.ulValueLen = new NativeLong(NativeLong.SIZE);
    }

    /**
     * Creates an attribute with a boolean value.
     */
    public Attribute(long attributeType, boolean value) {
        super();
        this.type = new NativeLong(attributeType);
        this.pValue = new Memory(1);
        this.pValue.setByte(0, (byte) (value ? 1 : 0));
        this.ulValueLen = new NativeLong(1);
    }

    /**
     * Returns the attribute type.
     */
    public long getType() {
        return type != null ? type.longValue() : 0;
    }

    /**
     * Returns the value length.
     */
    public long getValueLength() {
        return ulValueLen != null ? ulValueLen.longValue() : 0;
    }

    /**
     * Returns the value as a byte array.
     */
    public byte[] getValueAsBytes() {
        if (pValue == null || getValueLength() == 0) {
            return new byte[0];
        }
        return pValue.getByteArray(0, (int) getValueLength());
    }

    /**
     * Returns the value as a NativeLong.
     */
    public NativeLong getValueAsNativeLong() {
        if (pValue == null) {
            return new NativeLong(0);
        }
        if (NativeLong.SIZE == 8) {
            return new NativeLong(pValue.getLong(0));
        } else {
            return new NativeLong(pValue.getInt(0));
        }
    }

    /**
     * Returns the value as a long.
     */
    public long getValueAsLong() {
        return getValueAsNativeLong().longValue();
    }

    /**
     * Returns the value as a boolean.
     */
    public boolean getValueAsBoolean() {
        if (pValue == null) {
            return false;
        }
        return pValue.getByte(0) != 0;
    }

    /**
     * Returns the value as a string.
     */
    public String getValueAsString() {
        byte[] bytes = getValueAsBytes();
        if (bytes.length == 0) {
            return "";
        }
        return new String(bytes, StandardCharsets.UTF_8);
    }

    /**
     * Allocates memory for the value with the specified length.
     */
    public void allocateValue(long length) {
        if (length > 0) {
            this.pValue = new Memory(length);
            this.ulValueLen = new NativeLong(length);
        }
    }

    // Factory methods for common attributes

    /**
     * Creates an attribute for object class query/filter.
     */
    public static Attribute forClass(long objectClass) {
        return new Attribute(AttributeType.CLASS, objectClass);
    }

    /**
     * Creates an attribute for certificate class.
     */
    public static Attribute forCertificate() {
        return forClass(ObjectClass.CERTIFICATE);
    }

    /**
     * Creates an attribute for private key class.
     */
    public static Attribute forPrivateKey() {
        return forClass(ObjectClass.PRIVATE_KEY);
    }

    /**
     * Creates an attribute for ID query.
     */
    public static Attribute forId() {
        return new Attribute(AttributeType.ID);
    }

    /**
     * Creates an attribute for ID with value.
     */
    public static Attribute forId(byte[] id) {
        return new Attribute(AttributeType.ID, id);
    }

    /**
     * Creates an attribute for value query.
     */
    public static Attribute forValue() {
        return new Attribute(AttributeType.VALUE);
    }

    public static class ByReference extends Attribute implements Structure.ByReference {}
    public static class ByValue extends Attribute implements Structure.ByValue {}
}
