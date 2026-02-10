import { __decorate } from "tslib";
import { AsnProp, AsnType, AsnTypeTypes } from "@peculiar/asn1-schema";
import { IssuerAndSerialNumber } from "./issuer_and_serial_number";
import { SubjectKeyIdentifier } from "@peculiar/asn1-x509";
let SignerIdentifier = class SignerIdentifier {
    constructor(params = {}) {
        Object.assign(this, params);
    }
};
__decorate([
    AsnProp({ type: SubjectKeyIdentifier, context: 0, implicit: true })
], SignerIdentifier.prototype, "subjectKeyIdentifier", void 0);
__decorate([
    AsnProp({ type: IssuerAndSerialNumber })
], SignerIdentifier.prototype, "issuerAndSerialNumber", void 0);
SignerIdentifier = __decorate([
    AsnType({ type: AsnTypeTypes.Choice })
], SignerIdentifier);
export { SignerIdentifier };
