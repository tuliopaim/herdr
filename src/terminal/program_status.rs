//! PTY-local OSC 7501 records. Socket reports still own session identity.
use std::time::Instant;

use crate::detect::AgentState;
use crate::ghostty::{ProgramStatus, ProgramStatusEvent, ProgramStatusState};

#[derive(Default)]
pub(super) struct ProgramStatusRecords {
    // Oldest update first. Bounded independently of attacker-chosen IDs.
    records: Vec<(ProgramStatus, Instant)>,
    selected_index: Option<usize>,
    selected_app: Option<String>,
}

impl ProgramStatusRecords {
    pub(super) fn apply(&mut self, events: Vec<ProgramStatusEvent>, now: Instant) {
        for event in events {
            match event {
                ProgramStatusEvent::ShellPrompt => self.process_exit(now),
                ProgramStatusEvent::Report(report) => {
                    if report.state == ProgramStatusState::Clear {
                        self.records.retain(|(record, _)| {
                            !report.id.is_empty()
                                && record.id != report.id
                                && !record
                                    .id
                                    .strip_prefix(&report.id)
                                    .is_some_and(|s| s.starts_with('/'))
                        });
                    } else {
                        self.records.retain(|(record, _)| record.id != report.id);
                        if self.records.len() == 256 {
                            self.records.remove(0);
                        }
                        self.records.push((report, now));
                    }
                }
            }
        }
        self.refresh_selection();
    }

    pub(super) fn process_exit(&mut self, observed_at: Instant) {
        self.records.retain(|(record, updated_at)| {
            *updated_at > observed_at
                || matches!(
                    record.state,
                    ProgramStatusState::Done | ProgramStatusState::Error
                )
        });
        self.refresh_selection();
    }

    fn selected(&self) -> Option<&ProgramStatus> {
        self.selected_index.map(|index| &self.records[index].0)
    }

    fn refresh_selection(&mut self) {
        // Blocked children win over root working. Newest update wins ties.
        self.selected_index = self
            .records
            .iter()
            .enumerate()
            .max_by_key(|(index, (record, _))| {
                let priority = match record.state {
                    ProgramStatusState::Blocked => 4,
                    ProgramStatusState::Working => 3,
                    ProgramStatusState::Error => 2,
                    ProgramStatusState::Done => 1,
                    _ => 0,
                };
                (priority, *index)
            })
            .map(|(index, _)| index);
        self.selected_app = self.inherited_app().map(str::to_owned);
    }

    pub(super) fn state(&self) -> Option<AgentState> {
        self.selected().map(|record| match record.state {
            ProgramStatusState::Working => AgentState::Working,
            ProgramStatusState::Blocked => AgentState::Blocked,
            // Herdr represents completed results as idle plus unseen, including failures.
            _ => AgentState::Idle,
        })
    }

    pub(super) fn app(&self) -> Option<&str> {
        self.selected_app.as_deref()
    }

    pub(super) fn explain(&self) -> Option<serde_json::Value> {
        let record = self.selected()?;
        Some(serde_json::json!({
            "state": match record.state {
                ProgramStatusState::Idle => "idle", ProgramStatusState::Working => "working",
                ProgramStatusState::Done => "done", ProgramStatusState::Blocked => "blocked",
                ProgramStatusState::Error => "error", ProgramStatusState::Clear => "clear",
            },
            "id": record.id, "app": self.app(), "records": self.records.len(),
        }))
    }

    fn inherited_app(&self) -> Option<&str> {
        let record = self.selected()?;
        if !record.app.is_empty() {
            return Some(&record.app);
        }
        let mut id = record.id.as_str();
        while !id.is_empty() {
            id = id.rsplit_once('/').map_or("", |(parent, _)| parent);
            if let Some((ancestor, _)) = self
                .records
                .iter()
                .find(|(r, _)| r.id == id && !r.app.is_empty())
            {
                return Some(&ancestor.app);
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::Agent;
    use crate::terminal::{TerminalId, TerminalState};

    fn setup() -> (crate::ghostty::Terminal, TerminalState) {
        let mut vt = crate::ghostty::Terminal::new(80, 24, 0).unwrap();
        vt.enable_program_status().unwrap();
        (vt, TerminalState::new(TerminalId::alloc(), "/tmp".into()))
    }

    fn feed(vt: &mut crate::ghostty::Terminal, terminal: &mut TerminalState, bytes: &[u8]) {
        vt.write(bytes);
        terminal.apply_program_status(vt.take_program_status_events(), Instant::now());
    }

    #[test]
    fn program_status_split_reads_and_socket_authority() {
        let report = b"\x1b]7501;state=blocked:kind=question:app=pi:msg=Q29udGludWU/\x1b\\";
        for split in 0..=report.len() {
            let (mut vt, mut terminal) = setup();
            feed(&mut vt, &mut terminal, &report[..split]);
            feed(&mut vt, &mut terminal, &report[split..]);
            assert_eq!(terminal.state, AgentState::Blocked);
            terminal.set_hook_authority(
                "pi".into(),
                "pi".into(),
                AgentState::Working,
                None,
                Some(1),
            );
            assert_eq!(terminal.state, AgentState::Blocked);
            terminal.set_hook_authority("pi".into(), "pi".into(), AgentState::Idle, None, Some(2));
            assert_eq!(terminal.state, AgentState::Blocked);
            terminal.set_detected_state(Some(Agent::Pi), AgentState::Working);
            assert_eq!(terminal.state, AgentState::Blocked);
            feed(
                &mut vt,
                &mut terminal,
                b"\x1b]7501;state=working:app=pi\x07",
            );
            assert_eq!(terminal.state, AgentState::Working);
        }
    }

    #[test]
    fn program_status_negotiates_before_da_only_with_consumer() {
        use std::sync::{Arc, Mutex};
        let mut vt = crate::ghostty::Terminal::new(80, 24, 0).unwrap();
        let replies = Arc::new(Mutex::new(Vec::new()));
        let sink = replies.clone();
        vt.set_write_pty_callback(move |bytes| sink.lock().unwrap().extend_from_slice(bytes))
            .unwrap();
        vt.write(b"\x1b]7501;?\x1b\\");
        assert!(replies.lock().unwrap().is_empty());
        vt.enable_program_status().unwrap();
        vt.write(b"\x1b]7501;?");
        assert!(replies.lock().unwrap().is_empty());
        vt.write(b"\x1b\\\x1b[c");
        assert!(replies
            .lock()
            .unwrap()
            .starts_with(b"\x1b]7501;?\x1b\\\x1b["));
        assert!(vt.take_program_status_events().is_empty());
    }

    #[test]
    fn program_status_invalid_input_cannot_replace_authority() {
        let (mut vt, mut terminal) = setup();
        feed(
            &mut vt,
            &mut terminal,
            b"\x1b]7501;state=working:app=pi\x07",
        );
        for body in [
            "app=pi",
            "state=unknown",
            "state=blocked:id=a//b",
            "state=blocked:msg=AA==",
            "state=blocked:msg=woA=",
            "state=blocked:title=fw==",
            "state=blocked:msg=not_base64",
        ] {
            feed(
                &mut vt,
                &mut terminal,
                format!("\x1b]7501;{body}\x07").as_bytes(),
            );
            assert_eq!(terminal.state, AgentState::Working, "{body}");
        }
        for body in [
            format!("state=blocked:app={}", "a".repeat(33)),
            format!("state=blocked:msg={}", "A".repeat(5000)),
        ] {
            feed(
                &mut vt,
                &mut terminal,
                format!("\x1b]7501;{body}\x1b\\").as_bytes(),
            );
            assert_eq!(terminal.state, AgentState::Working);
        }
        // A cancelled OSC must not reach the consumer.
        feed(
            &mut vt,
            &mut terminal,
            b"\x1b]7501;state=blocked:app=pi\x18\x07",
        );
        assert_eq!(terminal.state, AgentState::Working);
    }

    #[test]
    fn program_status_hierarchy_clear_and_whole_record_replacement() {
        let (mut vt, mut terminal) = setup();
        feed(
            &mut vt,
            &mut terminal,
            b"\x1b]7501;state=working:id=job:app=pi\x07\x1b]7501;state=blocked:id=job/question\x07",
        );
        assert_eq!(terminal.state, AgentState::Blocked);
        assert_eq!(terminal.effective_agent_label(), Some("pi"));
        feed(&mut vt, &mut terminal, b"\x1b]7501;state=clear:id=jo\x07");
        assert_eq!(terminal.state, AgentState::Blocked);
        feed(
            &mut vt,
            &mut terminal,
            b"\x1b]7501;state=working:state=idle:id=job/question:unknown=value:bad pair\x07",
        );
        assert_eq!(terminal.state, AgentState::Working);
        feed(&mut vt, &mut terminal, b"\x1b]7501;state=clear:id=job\x07");
        assert!(terminal.program_status_explain().is_none());
        feed(
            &mut vt,
            &mut terminal,
            b"\x1b]7501;state=working:app=pi\x07\x1b]7501;state=idle\x07",
        );
        assert_eq!(terminal.effective_agent_label(), None);
    }

    #[test]
    fn program_status_lifetimes_reset_and_alternate_screen() {
        for status in ["working", "blocked", "idle", "done", "error"] {
            let (mut vt, mut terminal) = setup();
            feed(
                &mut vt,
                &mut terminal,
                format!("\x1b]7501;state={status}:app=pi\x07").as_bytes(),
            );
            feed(&mut vt, &mut terminal, b"\x1b[?1049h\x1b[?1049l\x1b[!p");
            assert!(terminal.program_status_explain().is_some());
            feed(&mut vt, &mut terminal, b"\x1b]133;A\x07");
            assert_eq!(
                terminal.program_status_explain().is_some(),
                matches!(status, "done" | "error")
            );
            feed(
                &mut vt,
                &mut terminal,
                format!("\x1b]7501;state={status}:app=pi\x07").as_bytes(),
            );
            terminal.set_detected_state_with_screen_signals_at(
                Some(Agent::Pi),
                AgentState::Unknown,
                false,
                false,
                false,
                true,
                Instant::now(),
            );
            assert_eq!(
                terminal.program_status_explain().is_some(),
                matches!(status, "done" | "error")
            );
            feed(&mut vt, &mut terminal, b"\x1bc");
            assert!(terminal.program_status_explain().is_none());
        }
    }

    #[test]
    fn program_status_record_cap_evicts_oldest_update() {
        let (mut vt, mut terminal) = setup();
        for id in 0..257 {
            feed(
                &mut vt,
                &mut terminal,
                format!("\x1b]7501;state=idle:app=pi:id={id}\x07").as_bytes(),
            );
        }
        let explain = terminal.program_status_explain().unwrap();
        assert_eq!(explain["records"], 256);
        assert_eq!(explain["id"], "256");
        feed(&mut vt, &mut terminal, b"\x1b]7501;state=clear\x07");
        assert!(terminal.program_status_explain().is_none());
    }
}
