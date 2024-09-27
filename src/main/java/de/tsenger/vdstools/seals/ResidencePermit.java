package de.tsenger.vdstools.seals;

import java.util.List;

import org.tinylog.Logger;

import de.tsenger.vdstools.DataParser;

/**
 * @author Tobias Senger
 *
 */
public class ResidencePermit extends DigitalSeal {

    public ResidencePermit(VdsHeader vdsHeader, VdsMessage vdsMessage, VdsSignature vdsSignature) {
        super(vdsHeader, vdsMessage, vdsSignature);
        parseDocumentFeatures(vdsMessage.getDocumentFeatures());
    }

    private void parseDocumentFeatures(List<DocumentFeatureDto> features) {
        for (DocumentFeatureDto feature : features) {
            switch (feature.getTag()) {
            case 0x02:
                String mrz = DataParser.decodeC40(feature.getValue()).replace(' ', '<');
                StringBuilder sb = new StringBuilder(mrz);
                sb.insert(36, '\n');
                featureMap.put(Feature.MRZ, sb.toString());
                break;
            case 0x03:
                String passportNumber = DataParser.decodeC40(feature.getValue());
                featureMap.put(Feature.PASSPORT_NUMBER, passportNumber);
                break;
            default:
                Logger.warn("found unknown tag: 0x" + String.format("%02X ", feature.getTag()));
            }
        }

    }
    
    

}
