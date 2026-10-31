use super::*;

impl DurableVault {
    /// Trusted clock is sampled again after the last intent commit, immediately before handoff.
    pub(crate) fn use_secret<F>(&mut self, ctx: &AuthenticatedContext, task: Uuid, request: PrivateUse,
        clock: &mut impl FnMut() -> Time, deliver: F) -> Result<DeliveryReceipt, Error>
    where F: FnOnce(&BTreeMap<Field, &str>) -> Result<DeliveryStatus, Error> {
        let prepared_at = clock();
        let key = RequestKey { owner: ctx.owner.clone(), principal: ctx.principal.clone(), task, id: request.request };
        let bytes = Zeroizing::new(serde_json::to_vec(&request).map_err(|_| Error::Invalid)?);
        let fingerprint: [u8; 32] = Sha256::digest(bytes.as_slice()).into();
        let attempt = Uuid::new_v4();
        let cached = self.apply(|app| {
            let prepared_at = app.clock(prepared_at)?;
            if request.request.is_nil() { return Err(Error::Invalid); }
            app.select(ctx, task, request.record, &request.fields, Permission::SecretUse, Some(&request.destination), prepared_at)?;
            let record = app.record(ctx, request.record)?;
            if request.action != PrivateAction::Use && (record.kind != CredentialKind::Login
                || !request.fields.contains(&Field::Username) || !request.fields.contains(&Field::Password))
            { return Err(Error::Invalid); }
            let version = record.secret_version;
            if request.action == PrivateAction::Register && record.restored { return Err(Error::Conflict); }
            if app.requests.contains_key(&key) { return Err(Error::ReplayConflict); }
            if let Some((id, previous)) = app.deliveries.iter().find(|(_, d)| d.key == key) {
                if previous.version != version { return Err(Error::Denied); }
                if previous.fingerprint != fingerprint { return Err(Error::ReplayConflict); }
                if !previous.dispatched { return Err(Error::Denied); }
                let status = previous.status.ok_or(Error::RecoveryRequired)?;
                return Ok(Some(DeliveryReceipt { attempt: *id, status }));
            }
            // Once a registration might have dispatched, neither a new ID nor a model report may replay it.
            if request.action == PrivateAction::Register && app.deliveries.values().any(|d|
                d.record == request.record && d.action == PrivateAction::Register && d.dispatched)
            { return Err(Error::Conflict); }
            if app.deliveries.len() >= 10_000 { return Err(Error::Capacity); }
            app.deliveries.insert(attempt, DeliveryAttempt {
                task, record: request.record, version, destination: request.destination.clone(), fields: request.fields.clone(),
                status: None, key: key.clone(), fingerprint, action: request.action, dispatched: true,
            });
            if request.action == PrivateAction::Register {
                app.records.get_mut(&request.record).ok_or(Error::Denied)?.signup = SignupState::Submitted;
            }
            Ok(None)
        })?;
        if let Some(result) = cached { return Ok(result); }
        self.ready()?;
        // No persistence, queue wait or adapter setup may be inserted between this sample/check and callback.
        self.frozen = true;
        let handoff_at = clock();
        self.frozen = false;
        let authorized = self.app.clock(handoff_at).and_then(|effective|
            self.app.select(ctx, task, request.record, &request.fields, Permission::SecretUse,
                Some(&request.destination), effective).map(|values| (values, effective)));
        let (values, handoff_at) = match authorized {
            Ok(authorized) => authorized,
            Err(error) => {
                self.apply(|app| {
                    let d = app.deliveries.get_mut(&attempt).ok_or(Error::RecoveryRequired)?;
                    d.dispatched = false;
                    d.status = Some(DeliveryStatus::Rejected);
                    if request.action == PrivateAction::Register {
                        app.records.get_mut(&request.record).ok_or(Error::RecoveryRequired)?.signup = SignupState::Pending;
                    }
                    Ok(())
                }).map_err(|_| { self.frozen = true; Error::RecoveryRequired })?;
                return Err(error);
            }
        };
        let private = values.0.iter().map(|(f, v)| (*f, v.as_str())).collect();
        // A panic leaves a durable unfinished intent and a frozen owner, even if a caller catches it.
        self.frozen = true;
        let delivered = deliver(&private);
        self.frozen = false;
        let status = delivered.as_ref().copied().unwrap_or(DeliveryStatus::Unknown);
        self.apply(|app| {
            app.deliveries.get_mut(&attempt).ok_or(Error::RecoveryRequired)?.status = Some(status);
            let record = app.records.get_mut(&request.record).ok_or(Error::RecoveryRequired)?;
            match (request.action, status) {
                (PrivateAction::Register, DeliveryStatus::Accepted) => record.signup = SignupState::ReportedSuccess,
                (PrivateAction::Register, DeliveryStatus::Rejected) => record.signup = SignupState::Rejected,
                (PrivateAction::Register, DeliveryStatus::HumanRequired) => record.signup = SignupState::HumanRequired,
                (PrivateAction::Register, DeliveryStatus::Unknown) => record.signup = SignupState::Unknown,
                (PrivateAction::Login, DeliveryStatus::Accepted) => record.signup = SignupState::VerifiedLogin,
                _ => {},
            }
            app.audit(AuditEvent { task, record: request.record, request: None, action: AuditAction::SecretUse,
                at: handoff_at, principal: ctx.principal.clone() });
            Ok(())
        }).map_err(|_| { self.frozen = true; Error::RecoveryRequired })?;
        // Adapter failure cannot make a claim about storage publication or invite replay.
        delivered.map_err(|_| Error::InteractionRequired)?;
        Ok(DeliveryReceipt { attempt, status })
    }
}
