import { __decorate } from "tslib";
import { AsnProp, AsnPropTypes } from "@peculiar/asn1-schema";
import { ClassList, ClassListFlags } from "./class_list";
import { SecurityCategory } from "./security_category";
export class Clearance {
    constructor(params = {}) {
        this.policyId = "";
        this.classList = new ClassList(ClassListFlags.unclassified);
        Object.assign(this, params);
    }
}
__decorate([
    AsnProp({ type: AsnPropTypes.ObjectIdentifier })
], Clearance.prototype, "policyId", void 0);
__decorate([
    AsnProp({ type: ClassList, defaultValue: new ClassList(ClassListFlags.unclassified) })
], Clearance.prototype, "classList", void 0);
__decorate([
    AsnProp({ type: SecurityCategory, repeated: "set" })
], Clearance.prototype, "securityCategories", void 0);
