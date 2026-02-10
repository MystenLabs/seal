import { __decorate } from "tslib";
import { AsnProp, AsnPropTypes } from "@peculiar/asn1-schema";
import { AlgorithmIdentifier } from "@peculiar/asn1-x509";
export var DigestedObjectType;
(function (DigestedObjectType) {
    DigestedObjectType[DigestedObjectType["publicKey"] = 0] = "publicKey";
    DigestedObjectType[DigestedObjectType["publicKeyCert"] = 1] = "publicKeyCert";
    DigestedObjectType[DigestedObjectType["otherObjectTypes"] = 2] = "otherObjectTypes";
})(DigestedObjectType || (DigestedObjectType = {}));
export class ObjectDigestInfo {
    constructor(params = {}) {
        this.digestedObjectType = DigestedObjectType.publicKey;
        this.digestAlgorithm = new AlgorithmIdentifier();
        this.objectDigest = new ArrayBuffer(0);
        Object.assign(this, params);
    }
}
__decorate([
    AsnProp({ type: AsnPropTypes.Enumerated })
], ObjectDigestInfo.prototype, "digestedObjectType", void 0);
__decorate([
    AsnProp({ type: AsnPropTypes.ObjectIdentifier, optional: true })
], ObjectDigestInfo.prototype, "otherObjectTypeID", void 0);
__decorate([
    AsnProp({ type: AlgorithmIdentifier })
], ObjectDigestInfo.prototype, "digestAlgorithm", void 0);
__decorate([
    AsnProp({ type: AsnPropTypes.BitString })
], ObjectDigestInfo.prototype, "objectDigest", void 0);
