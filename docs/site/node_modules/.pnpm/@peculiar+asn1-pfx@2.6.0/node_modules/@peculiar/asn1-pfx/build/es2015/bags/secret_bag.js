import { __decorate } from "tslib";
import { AsnProp, AsnPropTypes } from "@peculiar/asn1-schema";
export class SecretBag {
    constructor(params = {}) {
        this.secretTypeId = "";
        this.secretValue = new ArrayBuffer(0);
        Object.assign(this, params);
    }
}
__decorate([
    AsnProp({ type: AsnPropTypes.ObjectIdentifier })
], SecretBag.prototype, "secretTypeId", void 0);
__decorate([
    AsnProp({ type: AsnPropTypes.Any, context: 0 })
], SecretBag.prototype, "secretValue", void 0);
