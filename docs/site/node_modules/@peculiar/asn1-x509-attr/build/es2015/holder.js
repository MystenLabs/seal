import { __decorate } from "tslib";
import { AsnProp } from "@peculiar/asn1-schema";
import { IssuerSerial } from "./issuer_serial";
import { GeneralNames } from "@peculiar/asn1-x509";
import { ObjectDigestInfo } from "./object_digest_info";
export class Holder {
    constructor(params = {}) {
        Object.assign(this, params);
    }
}
__decorate([
    AsnProp({ type: IssuerSerial, implicit: true, context: 0, optional: true })
], Holder.prototype, "baseCertificateID", void 0);
__decorate([
    AsnProp({ type: GeneralNames, implicit: true, context: 1, optional: true })
], Holder.prototype, "entityName", void 0);
__decorate([
    AsnProp({ type: ObjectDigestInfo, implicit: true, context: 2, optional: true })
], Holder.prototype, "objectDigestInfo", void 0);
