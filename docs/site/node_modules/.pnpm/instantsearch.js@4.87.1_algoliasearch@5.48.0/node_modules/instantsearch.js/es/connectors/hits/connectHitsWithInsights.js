import { withInsights } from "../../lib/insights/index.js";
import connectHits from "./connectHits.js";

/**
 * Due to https://github.com/microsoft/web-build-tools/issues/1050, we need
 * Connector<...> imported in this file, even though it is only used implicitly.
 * This _uses_ Connector<...> so it is not accidentally removed by someone.
 */
// eslint-disable-next-line @typescript-eslint/no-unused-vars

var connectHitsWithInsights = withInsights(connectHits);
export default connectHitsWithInsights;