package de.tsenger.vdstools.vds;

import java.util.HashMap;

//@formatter:off
public enum VdsType {
    ARRIVAL_ATTESTATION(0xfd02), 
    ICAO_EMERGENCY_TRAVEL_DOCUMENT(0x5e03), 
    ICAO_VISA(0x5d01),
    ADDRESS_STICKER_PASSPORT(0xf80a), 
    ADDRESS_STICKER_ID(0xf908), 
    RESIDENCE_PERMIT(0xfb06),
    SOCIAL_INSURANCE_CARD(0xfc04), 
    SUPPLEMENTARY_SHEET(0xfa06), 
    ALIENS_LAW(0x01fe),
	TEMP_PASSPORT(0xf60d),
	TEMP_PERSO(0xf70b),
	FICTION_CERT(0xf50c),
	PERMANT_RESIDENCE_CERT(0xf48f);

    private final int reference;
    private static HashMap<Integer, VdsType> map = new HashMap<>();

    VdsType(int reference) {
        this.reference = reference;
    }

    static {
        for (VdsType vdsType : VdsType.values()) {
            map.put(vdsType.reference, vdsType);
        }
    }

    public static VdsType valueOf(int vdsType) {
        return map.get(vdsType);
    }

    public int getValue() {
        return reference;
    }
}
