//! The GET loop over lnurlcash-core's pure `protocol` layer.
//!
//! The core ships a reqwest `Client` too, but it draws a rotate's fresh secret
//! and sends it inside one call, leaving no point at which the wallet can
//! write that secret to disk first. So this module runs a [`Request`] the
//! wallet already built - and persisted - and classifies failures exactly as
//! the core's client does: a transport failure on a mutation is ambiguous,
//! never a failure.

use std::time::Duration;

use lnurlcash_core::protocol::{self, MutationKind, MutationResponse, Policy, Request};
use lnurlcash_core::{is_allowed_service_url, Error, Result};
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct Http {
    client: reqwest::Client,
    pub policy: Policy,
    /// Re-sends of a rotate whose answer the transport lost. LUD-25 requires a
    /// mint to answer a byte-identical retry with its original success, so a
    /// retry resolves ambiguity rather than compounding it. Never applied to
    /// a melt.
    pub mutation_retries: u32,
}

impl Default for Http {
    fn default() -> Self {
        Self::new(Duration::from_secs(30))
    }
}

impl Http {
    pub fn new(timeout: Duration) -> Self {
        Http {
            client: reqwest::Client::builder()
                .timeout(timeout)
                .build()
                .unwrap_or_default(),
            policy: Policy::default(),
            mutation_retries: 1,
        }
    }

    pub async fn get(&self, request: &Request) -> Result<Value> {
        let attach = |err: Error| err.with_secrets(request.new_secrets.clone());
        if !is_allowed_service_url(&request.url) {
            return Err(Error::RequestRefused(
                "refusing to fetch that URL - only https, or http to a loopback or .onion host, is allowed".into(),
            ));
        }
        let response = match self.client.get(&request.url).send().await {
            Ok(response) => response,
            Err(err) if err.is_timeout() => {
                return Err(attach(Error::ambiguous(
                    "the service took too long to respond - its answer, if any, was lost",
                )))
            }
            Err(_) => {
                return Err(attach(Error::ambiguous(
                    "failed to reach the service - it may be offline or unreachable",
                )))
            }
        };
        let text = response
            .text()
            .await
            .map_err(|_| attach(Error::ambiguous("the service's response could not be read")))?;
        serde_json::from_str(&text).map_err(|_| {
            attach(Error::ambiguous(
                "the service returned an unreadable response",
            ))
        })
    }

    /// A request that changes nothing - an informational GET, a lookup, a
    /// payRequest - re-sent once if the transport lost it. Never for a
    /// mutation: those go through [`Http::mutation`] and its own rules.
    pub async fn read(&self, request: &Request) -> Result<Value> {
        match self.get(request).await {
            Err(err) if err.is_ambiguous() => {
                tokio::time::sleep(Duration::from_millis(300)).await;
                self.get(request).await
            }
            other => other,
        }
    }

    /// One mutating GET, re-sent unchanged while only ambiguity comes back.
    /// Whatever fails, the request's fresh secrets ride out on the error.
    pub async fn mutation(
        &self,
        request: &Request,
        kind: MutationKind,
    ) -> Result<MutationResponse> {
        let attempts = if kind == MutationKind::Melt {
            0
        } else {
            self.mutation_retries
        };
        let mut last = None;
        for _ in 0..=attempts {
            let outcome = match self.get(request).await {
                Ok(body) => protocol::parse_mutation(&body, kind, &request.outputs, self.policy),
                Err(err) => Err(err),
            };
            match outcome {
                Ok(response) => return Ok(response),
                Err(err) if err.is_ambiguous() => last = Some(err),
                Err(err) => return Err(err.with_secrets(request.new_secrets.clone())),
            }
        }
        Err(last
            .unwrap_or_else(|| Error::ambiguous("the mutation was never attempted"))
            .with_secrets(request.new_secrets.clone()))
    }
}

impl Http {
    /// A POST or DELETE outside the note protocol (registering a Lightning
    /// Address): same URL policy, `{"status":"ERROR"}` read as a refusal.
    pub async fn call(&self, method: reqwest::Method, url: &str) -> Result<Value> {
        if !is_allowed_service_url(url) {
            return Err(Error::RequestRefused("refusing to call that URL".into()));
        }
        let response = self
            .client
            .request(method, url)
            .send()
            .await
            .map_err(|_| Error::ambiguous("failed to reach the service"))?;
        let body: Value = serde_json::from_str(&response.text().await.unwrap_or_default())
            .map_err(|_| Error::ambiguous("the service returned an unreadable response"))?;
        if body.get("status").and_then(Value::as_str) == Some("ERROR") {
            let reason = body
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or_default();
            return Err(Error::ServiceRejected(reason.to_string()));
        }
        // FastAPI's own validation errors come back as {"detail": ...}
        if let Some(detail) = body.get("detail") {
            return Err(Error::ServiceRejected(detail.to_string()));
        }
        Ok(body)
    }
}
