//! Source updates may fill missing attribution; conflicting direct facts keep their history.
use crate::{FindingObservationContext, PostgresStoreError};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn fill_missing(current: &mut Value, incoming: &Value, path: &str, conflicts: &mut Vec<String>) {
    if current.is_null() {
        *current = incoming.clone();
        return;
    }
    if incoming.is_null() || current == incoming {
        return;
    }
    if path == "received_at" || path == "source" || path == "connector.implementation_version" {
        return;
    }
    if path.starts_with("fields.") {
        if current.get("basis").and_then(Value::as_str) == Some("unavailable") {
            *current = incoming.clone();
        }
        return;
    }
    if let (Some(old), Some(new)) = (current.as_object_mut(), incoming.as_object()) {
        for (key, value) in new {
            let next = if path.is_empty() {
                key.clone()
            } else {
                format!("{path}.{key}")
            };
            fill_missing(
                old.entry(key.clone()).or_insert(Value::Null),
                value,
                &next,
                conflicts,
            );
        }
    } else if current.as_array().is_some_and(Vec::is_empty) {
        *current = incoming.clone();
    } else {
        conflicts.push(path.into());
    }
}

pub(crate) async fn record_activity(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    finding: uuid::Uuid,
    usage: &FindingObservationContext,
) -> Result<bool, PostgresStoreError> {
    let Some(activity) = &usage.activity else {
        return Ok(false);
    };
    if activity.observation_id != usage.observation_id
        || activity.connector.instance_id != usage.connector_instance_id
        || activity.observed_at != usage.observed_at
    {
        return Err(PostgresStoreError::InvalidEntityResolution);
    }
    let incoming = serde_json::to_value(activity)?;
    let mut identity = incoming.clone();
    identity
        .as_object_mut()
        .expect("activity object")
        .remove("received_at");
    let digest = hex::encode(Sha256::digest(serde_json::to_vec(&identity)?));
    let old:Option<(Value,)>=sqlx::query_as("SELECT context FROM finding_activity WHERE finding_id=$1 AND observation_id=$2 AND installation_id=$3 FOR UPDATE")
        .bind(finding).bind(usage.observation_id).bind(usage.installation_id).fetch_optional(&mut **tx).await?;
    let mut context = old.map_or_else(|| incoming.clone(), |v| v.0);
    let mut conflicts = Vec::new();
    fill_missing(&mut context, &incoming, "", &mut conflicts);
    sqlx::query("INSERT INTO finding_activity(finding_id,observation_id,installation_id,connector_instance_id,observed_at,context) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(finding_id,observation_id) DO UPDATE SET context=EXCLUDED.context")
        .bind(finding).bind(usage.observation_id).bind(usage.installation_id).bind(usage.connector_instance_id).bind(usage.observed_at).bind(context).execute(&mut **tx).await?;
    let changed=sqlx::query("INSERT INTO finding_activity_revisions(finding_id,observation_id,digest,context,conflicts) VALUES($1,$2,$3,$4,$5) ON CONFLICT DO NOTHING")
        .bind(finding).bind(usage.observation_id).bind(digest).bind(incoming).bind(serde_json::to_value(conflicts)?).execute(&mut **tx).await?.rows_affected();
    Ok(changed > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_source_metadata_is_added_without_overwriting_a_known_actor() {
        let mut value = serde_json::json!({"actor":{"identity":{"email":"alice@example.test"}},"process":{},"fields":{"process":{"basis":"unavailable"}}});
        let update = serde_json::json!({"actor":{"identity":{"email":"bob@example.test"},"hostname":"laptop"},"process":{"executable":"claude"},"fields":{"process":{"basis":"observed"}}});
        let mut conflicts = Vec::new();
        fill_missing(&mut value, &update, "", &mut conflicts);
        assert_eq!(value["actor"]["identity"]["email"], "alice@example.test");
        assert_eq!(value["actor"]["hostname"], "laptop");
        assert_eq!(value["process"]["executable"], "claude");
        assert_eq!(value["fields"]["process"]["basis"], "observed");
        assert_eq!(conflicts, ["actor.identity.email"]);
    }
}
