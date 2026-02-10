import { __decorate } from "tslib";
import { AsnProp, AsnPropTypes } from "@peculiar/asn1-schema";
import { id_pkcs_9 } from "./types";
export class CRLBag {
    constructor(params = {}) {
        this.crlId = "";
        this.crltValue = new ArrayBuffer(0);
        Object.assign(this, params);
    }
}
__decorate([
    AsnProp({ type: AsnPropTypes.ObjectIdentifier })
], CRLBag.prototype, "crlId", void 0);
__decorate([
    AsnProp({ type: AsnPropTypes.Any, context: 0 })
], CRLBag.prototype, "crltValue", void 0);
export const id_crlTypes = `${id_pkcs_9}.23`;
export const id_x509CRL = `${id_crlTypes}.1`;
