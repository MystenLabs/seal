use crate::errors::InternalError;
use crate::errors::InternalError::{InvalidMVRName, OldPackageVersion};
use crate::types::Network;
use crate::{externals, mvr};
use sui_sdk::SuiClient;
use sui_types::base_types::ObjectID;

/// This function verifies if the package ID is the latest version of the package.
/// If an MVR name is provided, it also verifies that the MVR name points to this package.
/// Returns the first version of the package and a readable name.
pub async fn get_first_version_and_name(
    pkg_id: ObjectID,
    sui_client: &SuiClient,
    network: &Network,
    mvr_name: Option<&String>,
) -> Result<(ObjectID, String), InternalError> {
    match mvr_name {
        Some(mvr_name) => {
            let mvr_ref_pkg_id = mvr::mvr_forward_resolution(sui_client, network, mvr_name).await?;
            let (first, latest, mvr_latest) =
                externals::fetch_last_pkg_ids(&pkg_id, network, &mvr_ref_pkg_id).await?;
            if pkg_id != latest {
                return Err(OldPackageVersion(pkg_id, latest));
            } else if mvr_ref_pkg_id != mvr_latest {
                return Err(InvalidMVRName);
            }
            Ok((first, mvr_name.clone()))
        }
        None => {
            let (first, latest) = externals::fetch_first_and_last_pkg_id(&pkg_id, network).await?;
            if pkg_id != latest {
                return Err(OldPackageVersion(pkg_id, latest));
            }
            Ok((first, first.to_hex_uncompressed()))
        }
    }
}
