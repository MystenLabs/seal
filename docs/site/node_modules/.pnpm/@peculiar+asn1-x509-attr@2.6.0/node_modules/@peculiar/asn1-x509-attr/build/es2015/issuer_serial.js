import { __decorate } from "tslib";
import { AsnProp, AsnPropTypes, AsnIntegerArrayBufferConverter } from "@peculiar/asn1-schema";
import { GeneralNames } from "@peculiar/asn1-x509";
export class IssuerSerial {
    constructor(params = {}) {
        this.issuer = new GeneralNames();
        this.serial = new ArrayBuffer(0);
        this.issuerUID = new ArrayBuffer(0);
        Object.assign(this, params);
    }
}
__decorate([
    AsnProp({ type: GeneralNames })
], IssuerSerial.prototype, "issuer", void 0);
__decorate([
    AsnProp({ type: AsnPropTypes.Integer, converter: AsnIntegerArrayBufferConverter })
], IssuerSerial.prototype, "serial", void 0);
__decorate([
    AsnProp({ type: AsnPropTypes.BitString, optional: true })
], IssuerSerial.prototype, "issuerUID", void 0);
