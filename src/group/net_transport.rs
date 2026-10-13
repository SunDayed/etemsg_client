//! Real `GroupTransport` implementation: `Core`'s HTTPS channel plus signed REST.
//! The signed domain is the business fields (fixed order) plus `timestamp` and `nonce`, via `crypto::signed_request_body_with_key`.

use std::sync::Arc;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};

use super::service::{base64_decode, base64_encode};
use super::transport::*;
use crate::core::Core;

/// Group transport backed by `Core`.
pub struct CoreTransport {
    core: Arc<Core>,
    sid: String,
    username: String,
    priv_key: Arc<rsa::RsaPrivateKey>,
}

impl CoreTransport {
    pub fn new(core: Arc<Core>, sid: impl Into<String>) -> Result<Self> {
        let sid = sid.into();
        let username = core
            .username_of(&sid)
            .context("not logged in, cannot access the group API")?;
        let priv_key = core.priv_key(&sid).context("missing private key, cannot sign the group request")?;
        Ok(Self { core, sid, username, priv_key })
    }

    /// Build a signed body; `fields` are the business fields, in the order the server expects.
    fn signed_body(&self, fields: &[String], mut extra: Value) -> Result<Value> {
        let signed = crate::crypto::signed_request_body_with_key(&self.priv_key, fields)?;
        let (Some(obj), Some(sig_obj)) = (extra.as_object_mut(), signed.as_object()) else {
            bail!("the request body must be a JSON object");
        };
        for (k, v) in sig_obj {
            obj.insert(k.clone(), v.clone());
        }
        obj.insert("user_id".into(), json!(self.username));
        Ok(extra)
    }

    fn post(&self, path: &str, fields: &[String], body: Value) -> Result<Value> {
        let body = self.signed_body(fields, body)?;
        let res = self.core.rest(&self.sid, "POST", path, Some(body))?;
        check_ok(&res)?;
        Ok(res)
    }

    fn get(&self, path: &str, fields: &[String]) -> Result<Value> {
        // Signed GET: the signature travels in the query string (same idea as 1v1 download_file).
        let signed = crate::crypto::signed_request_body_with_key(&self.priv_key, fields)?;
        let ts = signed["timestamp"].as_i64().unwrap_or(0);
        let nonce = signed["nonce"].as_str().unwrap_or_default();
        let sig = signed["signature"].as_str().unwrap_or_default();
        let mut qs: Vec<String> = vec![format!("user_id={}", url_encode(&self.username))];
        qs.push(format!("timestamp={ts}"));
        qs.push(format!("nonce={}", url_encode(nonce)));
        qs.push(format!("signature={}", url_encode(sig)));
        let full = format!("{path}{}{}", if path.contains('?') { "&" } else { "?" }, qs.join("&"));
        let res = self.core.rest(&self.sid, "GET", &full, None)?;
        check_ok(&res)?;
        Ok(res)
    }
}

fn url_encode(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            other => other
                .to_string()
                .bytes()
                .map(|b| format!("%{b:02X}"))
                .collect(),
        })
        .collect()
}

/// The server always answers `{status, payload}` or `{status:"error", error:{code,message}}`.
fn check_ok(res: &Value) -> Result<()> {
    match res.get("status").and_then(|v| v.as_str()) {
        Some("ok") => Ok(()),
        _ => {
            let code = res
                .pointer("/error/code")
                .and_then(|v| v.as_str())
                .unwrap_or("UNKNOWN");
            let msg = res
                .pointer("/error/message")
                .and_then(|v| v.as_str())
                .unwrap_or("the server returned an error");
            bail!("{code}: {msg}")
        }
    }
}

fn payload(res: &Value) -> &Value {
    res.get("payload").unwrap_or(&Value::Null)
}

impl GroupTransport for CoreTransport {
    fn create_group(&self, req: &CreateGroupReq) -> Result<CreateGroupResp> {
        let name_b64 = base64_encode(&req.name_enc);
        let res = self.post(
            "/groups",
            &[req.group_id.clone(), name_b64.clone(), self.username.clone()],
            json!({ "group_id": req.group_id, "name_enc": name_b64, "creator": self.username }),
        )?;
        Ok(CreateGroupResp {
            group_id: payload(&res)
                .get("group_id")
                .and_then(|v| v.as_str())
                .unwrap_or(&req.group_id)
                .to_string(),
        })
    }

    fn get_group(&self, group_id: &str) -> Result<GroupDetail> {
        let res = self.get(
            &format!("/groups/{group_id}"),
            &[group_id.to_string(), self.username.clone()],
        )?;
        let p = payload(&res);
        let members = p
            .get("members")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .map(|m| MemberInfo {
                        user_id: m.get("user_id").and_then(|v| v.as_str()).unwrap_or("").into(),
                        role: m.get("role").and_then(|v| v.as_str()).unwrap_or("member").into(),
                        joined_epoch: m.get("joined_epoch").and_then(|v| v.as_u64()).unwrap_or(0),
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(GroupDetail {
            group_id: group_id.to_string(),
            name_enc: p
                .get("name_enc")
                .and_then(|v| v.as_str())
                .and_then(|s| base64_decode(s).ok()),
            creator: p.get("creator").and_then(|v| v.as_str()).unwrap_or("").into(),
            current_epoch: p.get("current_epoch").and_then(|v| v.as_u64()).unwrap_or(0),
            min_seq: p.get("min_seq").and_then(|v| v.as_u64()).unwrap_or(0),
            members,
        })
    }

    fn search_by_id(&self, group_id: &str) -> Result<Vec<GroupSearchHit>> {
        let res = self.get(
            &format!("/groups/search?by=id&q={group_id}"),
            &[self.username.clone(), "id".into(), group_id.to_string()],
        )?;
        let arr = payload(&res).as_array().cloned().unwrap_or_default();
        Ok(arr
            .iter()
            .map(|h| GroupSearchHit {
                group_id: h.get("group_id").and_then(|v| v.as_str()).unwrap_or("").into(),
                name_enc: h
                    .get("name_enc")
                    .and_then(|v| v.as_str())
                    .and_then(|s| base64_decode(s).ok()),
                creator: h.get("creator").and_then(|v| v.as_str()).unwrap_or("").into(),
                creator_public_key: h
                    .get("creator_public_key")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .into(),
                owner: h.get("owner").and_then(|v| v.as_str()).unwrap_or("").into(),
                owner_public_key: h
                    .get("owner_public_key")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .into(),
                member_count: h.get("member_count").and_then(|v| v.as_u64()).unwrap_or(0),
            })
            .collect())
    }

    fn upload_key_package(
        &self,
        group_id: &str,
        kp_id: &str,
        kp_b64: &str,
        kp_hash: &str,
    ) -> Result<()> {
        self.post(
            &format!("/groups/{group_id}/key-packages"),
            &[group_id.into(), self.username.clone(), kp_id.into(), kp_hash.into()],
            json!({ "kp_id": kp_id, "kp_b64": kp_b64, "kp_hash": kp_hash }),
        )?;
        Ok(())
    }

    fn fetch_key_package(&self, group_id: &str, kp_id: &str) -> Result<String> {
        let res = self.get(
            &format!("/groups/{group_id}/key-packages?kp_id={kp_id}"),
            &[group_id.into(), self.username.clone(), kp_id.into()],
        )?;
        payload(&res)
            .get("kp_b64")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .context("the server did not return a KeyPackage")
    }

    fn submit_join_request(&self, req: &JoinRequestRecord) -> Result<()> {
        self.post(
            &format!("/groups/{}/join_requests", req.group_id),
            &[
                req.group_id.clone(),
                req.request_id.clone(),
                req.applicant.clone(),
                req.kp_id.clone(),
                req.kp_hash.clone(),
                req.text_ct.clone(),
                req.text_iv.clone(),
                req.text_tag.clone(),
                req.text_wrapped_key.clone(),
            ],
            json!({
                "request_id": req.request_id, "applicant": req.applicant,
                "kp_id": req.kp_id, "kp_hash": req.kp_hash,
                "text_ct": req.text_ct, "text_iv": req.text_iv,
                "text_tag": req.text_tag, "text_wrapped_key": req.text_wrapped_key,
            }),
        )?;
        Ok(())
    }

    fn list_join_requests(&self, group_id: &str) -> Result<Vec<JoinRequestRecord>> {
        let res = self.get(
            &format!("/groups/{group_id}/join_requests"),
            &[group_id.into(), self.username.clone()],
        )?;
        Ok(as_array(payload(&res))
            .into_iter()
            .map(|r| JoinRequestRecord {
                request_id: s(&r, "request_id"),
                group_id: s(&r, "group_id"),
                applicant: s(&r, "applicant"),
                kp_id: s(&r, "kp_id"),
                kp_hash: s(&r, "kp_hash"),
                text_ct: s(&r, "text_ct"),
                text_iv: s(&r, "text_iv"),
                text_tag: s(&r, "text_tag"),
                text_wrapped_key: s(&r, "text_wrapped_key"),
                status: s(&r, "status"),
            })
            .collect())
    }

    fn decide_join_request(&self, group_id: &str, request_id: &str, allow: bool) -> Result<()> {
        let decision = if allow { "allow" } else { "deny" };
        self.post(
            &format!("/groups/{group_id}/join_requests/{request_id}/decide"),
            &[group_id.into(), request_id.into(), decision.into()],
            json!({ "decision": decision }),
        )?;
        Ok(())
    }

    fn push_commit(
        &self,
        group_id: &str,
        epoch: u64,
        parent_epoch: u64,
        kind: &str,
        commit_b64: &str,
        data_hash: &str,
    ) -> Result<()> {
        self.post(
            &format!("/groups/{group_id}/commits"),
            &[
                group_id.into(), epoch.to_string(), parent_epoch.to_string(),
                kind.into(), data_hash.into(),
            ],
            json!({
                "epoch": epoch, "parent_epoch": parent_epoch, "kind": kind,
                "commit_b64": commit_b64, "data_hash": data_hash,
            }),
        )?;
        Ok(())
    }

    fn list_commits_since(&self, group_id: &str, since_epoch: u64) -> Result<Vec<MlsLogRecord>> {
        let res = self.get(
            &format!("/groups/{group_id}/commits?since_epoch={since_epoch}"),
            &[group_id.into(), since_epoch.to_string()],
        )?;
        Ok(as_array(payload(&res))
            .into_iter()
            .map(log_record)
            .collect())
    }

    fn push_welcome(
        &self,
        group_id: &str,
        target_user: &str,
        welcome_b64: &str,
        data_hash: &str,
        epoch: u64,
    ) -> Result<()> {
        self.post(
            &format!("/groups/{group_id}/welcomes"),
            &[
                group_id.into(), target_user.into(), data_hash.into(), epoch.to_string(),
            ],
            json!({
                "target_user": target_user, "welcome_b64": welcome_b64,
                "data_hash": data_hash, "epoch": epoch,
            }),
        )?;
        Ok(())
    }

    fn list_welcomes(&self, group_id: &str) -> Result<Vec<MlsLogRecord>> {
        let res = self.get(
            &format!("/groups/{group_id}/welcomes"),
            &[group_id.into(), self.username.clone()],
        )?;
        Ok(as_array(payload(&res))
            .into_iter()
            .map(log_record)
            .collect())
    }

    fn send_group_message(
        &self,
        group_id: &str,
        epoch: u64,
        msg_id: &str,
        ciphertext: &str,
        msg_type: &str,
        file_id: &str,
    ) -> Result<u64> {
        let res = self.post(
            &format!("/groups/{group_id}/messages"),
            &[
                group_id.into(), msg_id.into(), epoch.to_string(),
                ciphertext.into(), msg_type.into(), file_id.into(),
            ],
            json!({
                "msg_id": msg_id, "epoch": epoch, "ciphertext": ciphertext,
                "msg_type": msg_type, "file_id": file_id,
            }),
        )?;
        Ok(payload(&res).get("seq").and_then(|v| v.as_u64()).unwrap_or(0))
    }

    fn list_messages_since(
        &self,
        group_id: &str,
        since_seq: u64,
        limit: usize,
    ) -> Result<PulledMessages> {
        let res = self.get(
            &format!("/groups/{group_id}/messages?since_seq={since_seq}&limit={limit}"),
            &[group_id.into(), since_seq.to_string()],
        )?;
        let p = payload(&res);
        let messages = as_array(p.get("messages").unwrap_or(&Value::Null))
            .into_iter()
            .map(|m| GroupMsgRecord {
                seq: m.get("seq").and_then(|v| v.as_u64()).unwrap_or(0),
                epoch: m.get("epoch").and_then(|v| v.as_u64()).unwrap_or(0),
                sender: s(&m, "sender"),
                msg_id: s(&m, "msg_id"),
                ciphertext: s(&m, "ciphertext"),
                msg_type: s(&m, "msg_type"),
                file_id: s(&m, "file_id"),
            })
            .collect();
        Ok(PulledMessages {
            my_role: res
                .pointer("/payload/my_role")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            messages,
            min_seq: p.get("min_seq").and_then(|v| v.as_u64()).unwrap_or(0),
        })
    }

    fn ack_messages(&self, group_id: &str, last_seq: u64) -> Result<()> {
        self.post(
            &format!("/groups/{group_id}/messages/ack"),
            &[group_id.into(), last_seq.to_string()],
            json!({ "last_seq": last_seq }),
        )?;
        Ok(())
    }

    fn leave_group(&self, group_id: &str, successor: Option<&str>) -> Result<()> {
        let body = match successor {
            Some(s) => json!({ "successor_user_id": s }),
            None => json!({}),
        };
        self.post(
            &format!("/groups/{group_id}/leave"),
            &[group_id.into(), self.username.clone()],
            body,
        )?;
        Ok(())
    }

    fn list_pending_removals(&self, group_id: &str) -> Result<Vec<String>> {
        let res = self.get(
            &format!("/groups/{group_id}/pending-removals"),
            &[group_id.into(), self.username.clone()],
        )?;
        Ok(res.pointer("/payload/targets")
            .and_then(|t| t.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default())
    }

    fn clear_pending_removals(&self, group_id: &str) -> Result<()> {
        self.post(
            &format!("/groups/{group_id}/pending-removals/clear"),
            &[group_id.into(), self.username.clone()],
            json!({}),
        )?;
        Ok(())
    }

    fn member_roles(&self, group_id: &str) -> Result<Vec<(String, String)>> {
        let res = self.get(
            &format!("/groups/{group_id}"),
            &[group_id.into(), self.username.clone()],
        )?;
        Ok(res
            .pointer("/payload/members")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|m| {
                        Some((
                            m.get("user_id")?.as_str()?.to_string(),
                            m.get("role")?.as_str()?.to_string(),
                        ))
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    fn start_owner_transfer(&self, group_id: &str, designee: &str) -> Result<()> {
        self.post(
            &format!("/groups/{group_id}/transfer"),
            &[group_id.into(), self.username.clone(), designee.into()],
            json!({ "designee": designee }),
        )?;
        Ok(())
    }

    fn pending_owner_transfer(&self, group_id: &str) -> Result<Option<OwnerTransferInfo>> {
        let res = self.get(
            &format!("/groups/{group_id}/transfer"),
            &[group_id.into(), self.username.clone()],
        )?;
        let t = res.pointer("/payload/transfer");
        let Some(t) = t.filter(|v| !v.is_null()) else { return Ok(None) };
        Ok(Some(OwnerTransferInfo {
            group_id: s(t, "group_id"),
            prev_owner: s(t, "prev_owner"),
            designee: s(t, "designee"),
            state: s(t, "state"),
        }))
    }

    fn decide_owner_transfer(&self, group_id: &str, accept: bool) -> Result<()> {
        let action = if accept { "accept" } else { "decline" };
        self.post(
            &format!("/groups/{group_id}/transfer/{action}"),
            &[group_id.into(), self.username.clone()],
            json!({}),
        )?;
        Ok(())
    }

    fn kick_member(&self, group_id: &str, target_user: &str) -> Result<()> {
        self.post(
            &format!("/groups/{group_id}/kick"),
            &[group_id.into(), self.username.clone(), target_user.into()],
            json!({ "target_user": target_user }),
        )?;
        Ok(())
    }

    fn dissolve_group(&self, group_id: &str) -> Result<()> {
        // DELETE also carries a JSON body: the server reads body and query alike; signed domain is [group_id, user_id].
        let body = self.signed_body(
            &[group_id.to_string(), self.username.clone()],
            json!({}),
        )?;
        let res = self
            .core
            .rest(&self.sid, "DELETE", &format!("/groups/{group_id}"), Some(body))?;
        check_ok(&res)?;
        Ok(())
    }
}

// JSON helpers

fn s(v: &Value, k: &str) -> String {
    v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string()
}

fn as_array(v: &Value) -> Vec<Value> {
    v.as_array().cloned().unwrap_or_default()
}

fn log_record(v: Value) -> MlsLogRecord {
    MlsLogRecord {
        seq: v.get("seq").and_then(|x| x.as_u64()).unwrap_or(0),
        epoch: v.get("epoch").and_then(|x| x.as_u64()).unwrap_or(0),
        kind: s(&v, "kind"),
        sender: s(&v, "sender"),
        target: s(&v, "target"),
        data_b64: s(&v, "data_b64"),
        data_hash: s(&v, "data_hash"),
    }
}
