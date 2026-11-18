//! Reading the existing installation's verified records before an in-place restore.

use pubky_switch_core::enc::unb64_array;
use pubky_switch_core::keys::{ScopeKey, ScopeKeys};
use pubky_switch_core::ops::{OpKind, SignedOp};
use pubky_switch_core::records::AppCert;
use pubky_switch_core::sealed::RecordValue;
use serde::Deserialize;

use super::{Collection, HeldRecord, RECORD_PREFIX, RecordContent, SharedRecord, store_corrupt};
use crate::app::state::{decode, key};
use crate::app::{AppError, uploaded};
use crate::store::StateStore;

/// Each stored record may be several MiB. Keep one row at a time, and decode
/// unrelated collections only far enough to read their name and policy.
pub(in crate::app) fn records<'a>(
    store: &'a dyn StateStore,
    ns: &'a str,
    selected: &'a AppCert,
    owner: &'a str,
    members: Vec<Collection>,
) -> impl Iterator<Item = Result<SharedRecord, AppError>> + 'a {
    let mut after = None;
    let mut installed = None;
    let mut done = members.is_empty();
    std::iter::from_fn(move || {
        while !done {
            let installed = match &installed {
                Some(cert) => cert,
                None => match previous_cert(store, ns, selected, owner) {
                    Ok(Some(cert)) => installed.insert(cert),
                    Ok(None) => {
                        done = true;
                        break;
                    }
                    Err(error) => {
                        done = true;
                        return Some(Err(error));
                    }
                },
            };
            let row = store.scan(ns, RECORD_PREFIX.as_bytes(), after.as_deref(), 1);
            let next = match row {
                Ok(mut page) => page.pop(),
                Err(error) => {
                    done = true;
                    return Some(Err(error.into()));
                }
            };
            let Some((key, value)) = next else {
                done = true;
                break;
            };
            let record = read(store, ns, (&key, &value), (installed, selected), &members);
            after = Some(key);
            match record {
                Ok(None) => continue,
                Ok(Some(record)) => return Some(Ok(record)),
                Err(error) => {
                    done = true;
                    return Some(Err(error));
                }
            }
        }
        None
    })
}

fn previous_cert(
    store: &dyn StateStore,
    ns: &str,
    selected: &AppCert,
    owner: &str,
) -> Result<Option<AppCert>, AppError> {
    let owners = store
        .get(ns, key::PROTOCOLS.as_bytes())?
        .ok_or_else(store_corrupt)?;
    let owners: Vec<String> = decode(&owners)?;
    if !owners.iter().any(|name| name == owner) {
        return Ok(None);
    }
    let bytes = store
        .get(ns, key::CERT.as_bytes())?
        .ok_or_else(store_corrupt)?;
    let cert =
        AppCert::verify(&decode(&bytes)?, &selected.identity()).map_err(|_| store_corrupt())?;
    if cert.app_id() != selected.app_id() || cert.signing_key() != selected.signing_key() {
        return Err(store_corrupt());
    }
    Ok(Some(cert))
}

#[derive(Deserialize)]
struct RecordPolicy {
    collection: String,
    policy: pubky_switch_core::ident::Policy,
}

fn read(
    store: &dyn StateStore,
    ns: &str,
    (key_bytes, bytes): (&[u8], &[u8]),
    (installed, selected): (&AppCert, &AppCert),
    members: &[Collection],
) -> Result<Option<SharedRecord>, AppError> {
    let header: RecordPolicy = decode(bytes)?;
    let scope = &header.policy.read_scope;
    if !installed.holds_scope(scope) || !selected.holds_scope(scope) {
        return Ok(None);
    }
    let Some(collection) = members
        .iter()
        .find(|c| c.name == header.collection && c.admits(&header.policy))
    else {
        return Ok(None);
    };
    let suffix = key_bytes
        .strip_prefix(RECORD_PREFIX.as_bytes())
        .ok_or_else(store_corrupt)?;
    let key = unb64_array::<32>(std::str::from_utf8(suffix).map_err(|_| store_corrupt())?)
        .map_err(|_| store_corrupt())?;
    let held: HeldRecord = decode(bytes)?;
    if matches!(held.content, RecordContent::Unreadable(_)) {
        return Ok(None);
    }
    let identity = installed.identity();
    let writer = AppCert::verify(&held.cert, &identity).map_err(|_| store_corrupt())?;
    let signed = SignedOp::verify(
        &held.op,
        &writer.signing_key(),
        &identity,
        Some(&writer.app_id()),
    )
    .map_err(|_| store_corrupt())?;
    let OpKind::RecordPut(put) = &signed.body().kind else {
        return Err(store_corrupt());
    };
    if writer.app_id() != held.writer
        || signed.item_hash()? != held.item_hash
        || put.key != key
        || put.policy != held.policy
        || put.value_sealed.scope != *scope
        || put.collection != collection.id(&identity)
    {
        return Err(store_corrupt());
    }
    let epoch = put.value_sealed.data_epoch;
    let mut keys = ScopeKeys::default();
    for name in std::iter::once(scope.as_str()).chain(pubky_switch_core::scopes::parent(scope)) {
        if let Some(bytes) = store.get(ns, key::scope(epoch, name).as_bytes())? {
            let held_key: ScopeKey = decode(&bytes)?;
            if held_key.data_epoch != epoch || held_key.scope != name {
                return Err(store_corrupt());
            }
            keys.keys.push(held_key);
            break;
        }
    }
    if keys.keys.is_empty() {
        return Ok(None);
    }
    let opened = put
        .value_sealed
        .open_with(&keys, &identity, &key)
        .map_err(|_| store_corrupt())?;
    let matches = match (opened, &held.content) {
        (RecordValue::Json(bytes), RecordContent::Value(cached)) => bytes == *cached,
        (RecordValue::Delete, RecordContent::Deleted) => true,
        _ => false,
    };
    if !matches {
        return Err(store_corrupt());
    }
    let divergent = store
        .get(ns, uploaded::divergent_key(&key).as_bytes())?
        .is_some();
    Ok(Some(held.shared(&key, divergent)))
}
