//! DTOs reserved for a future control-plane UI. V1.1 intentionally has no HTML UI.

use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct ScenarioSummary {
    pub id: String,
    pub name: String,
    pub description: String,
}
