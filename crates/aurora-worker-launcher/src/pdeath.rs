//! Two-way parent-death synchronization handshake.
//!
//! Pursuant to Milestone 10b Section 14 and Section 18:
//! Dedicated pipe pairs are mapped to low descriptors < 10:
//! - FD 6: `c2l_r` (Child-to-Launcher Read)
//! - FD 7: `c2l_w` (Child-to-Launcher Write)
//! - FD 8: `l2c_r` (Launcher-to-Child Read)
//! - FD 9: `l2c_w` (Launcher-to-Child Write)
//!
//! All pipe descriptors are staged above FD 9 before relocating to 6..=9 via `dup3`
//! so that neither `signalfd` (>= 10) nor overlapping pipe descriptors can be clobbered.
//!
//! Parent-death protection runs in two stages across the same pipe pairs:
//! 1. Immediately post-fork (before potentially blocking namespace/rootfs setup):
//!    install `PR_SET_PDEATHSIG(SIGKILL)` and execute the early parent-liveness
//!    handshake (`TOKEN_EARLY_ARMED` -> `TOKEN_EARLY_CONTINUE`).
//! 2. After all capability drops and security locks (`NoNewPrivs`, `PR_SET_DUMPABLE(0)`):
//!    re-arm `PR_SET_PDEATHSIG(SIGKILL)` and execute the final handshake
//!    (`TOKEN_ARMED` -> `TOKEN_CONTINUE`), closing the handshake pipes afterward.

use crate::{LauncherError, TOKEN_ARMED, TOKEN_CONTINUE, TOKEN_EARLY_ARMED, TOKEN_EARLY_CONTINUE};
use std::mem;
use std::os::unix::io::RawFd;

pub const FD_C2L_R: RawFd = 6;
pub const FD_C2L_W: RawFd = 7;
pub const FD_L2C_R: RawFd = 8;
pub const FD_L2C_W: RawFd = 9;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PdeathPausePoint {
    BeforeFirstPdeathsig,
    AfterFirstPdeathsig,
    BeforeEarlyContinue,
    LauncherBeforeEarlyContinue,
    LauncherBeforeFinalContinue,
}

impl PdeathPausePoint {
    pub fn parse(s: &str) -> Result<Self, LauncherError> {
        match s {
            "before-first-pdeathsig" => Ok(Self::BeforeFirstPdeathsig),
            "after-first-pdeathsig" => Ok(Self::AfterFirstPdeathsig),
            "before-early-continue" => Ok(Self::BeforeEarlyContinue),
            "launcher-before-early-continue" => Ok(Self::LauncherBeforeEarlyContinue),
            "launcher-before-final-continue" => Ok(Self::LauncherBeforeFinalContinue),
            other => Err(LauncherError::InvalidArgs(format!(
                "Invalid --test-pdeath-pause stage: '{other}'"
            ))),
        }
    }
}

pub struct PdeathTestHook {
    pub pause_point: PdeathPausePoint,
    pub ack_fd: Option<RawFd>,
    pub go_fd: Option<RawFd>,
}

impl PdeathTestHook {
    pub fn trigger(&self, current: PdeathPausePoint) -> Result<(), LauncherError> {
        if self.pause_point != current {
            return Ok(());
        }
        if let Some(fd) = self.ack_fd {
            write_exact_byte(fd, 0x01, "test hook ack")?;
            unsafe { libc::close(fd) };
        }
        if let Some(fd) = self.go_fd {
            let mut buf = [0u8; 1];
            let res = read_exact_byte(fd, &mut buf, "test hook go");
            unsafe { libc::close(fd) };
            match res {
                Ok(true) if buf[0] == 0x01 => {}
                Ok(_) => {
                    return Err(LauncherError::PdeathSync(
                        "Test hook go pipe closed or returned invalid token".to_string(),
                    ));
                }
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    pub fn close_fds(&self) {
        if let Some(fd) = self.ack_fd {
            unsafe { libc::close(fd) };
        }
        if let Some(fd) = self.go_fd {
            unsafe { libc::close(fd) };
        }
    }
}

pub enum HandshakeOutcome {
    Completed,
    ChildTerminated(Option<libc::c_int>),
}

pub struct PdeathLauncher {
    pub c2l_r: RawFd,
    pub l2c_w: RawFd,
}

pub struct PdeathChild {
    pub c2l_w: RawFd,
    pub l2c_r: RawFd,
}

/// Explicitly sets `SIGPIPE` to `SIG_IGN` so writes to a closed handshake pipe return `EPIPE`
/// deterministically rather than relying on Rust runtime initialization.
pub fn ensure_sigpipe_ignored() -> Result<(), LauncherError> {
    let prev = unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };
    if prev == libc::SIG_ERR {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(LauncherError::Os("signal(SIGPIPE, SIG_IGN)", errno));
    }
    Ok(())
}

/// Installs `PR_SET_PDEATHSIG(SIGKILL)` and fails closed if `prctl` returns an error.
pub fn install_pdeathsig_sigkill() -> Result<(), LauncherError> {
    let ret = unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) };
    if ret != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(LauncherError::Os("prctl(PR_SET_PDEATHSIG, SIGKILL)", errno));
    }
    Ok(())
}

fn write_exact_byte(fd: RawFd, byte: u8, context: &'static str) -> Result<(), LauncherError> {
    let buf = [byte];
    loop {
        let written = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, 1) };
        if written == 1 {
            return Ok(());
        }
        if written < 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if errno == libc::EINTR {
                continue;
            }
            return Err(LauncherError::PdeathSync(format!(
                "{context}: write failed with errno {errno}"
            )));
        }
        return Err(LauncherError::PdeathSync(format!(
            "{context}: unexpected write return {written}"
        )));
    }
}

fn read_exact_byte(
    fd: RawFd,
    out: &mut [u8; 1],
    context: &'static str,
) -> Result<bool, LauncherError> {
    loop {
        let n = unsafe { libc::read(fd, out.as_mut_ptr() as *mut libc::c_void, 1) };
        if n == 1 {
            return Ok(true);
        }
        if n == 0 {
            return Ok(false);
        }
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno == libc::EINTR {
            continue;
        }
        return Err(LauncherError::PdeathSync(format!(
            "{context}: read failed with errno {errno}"
        )));
    }
}

/// Stages an FD to >= 10 via `F_DUPFD_CLOEXEC` so it cannot collide with target FDs 6..=9.
fn stage_above_9(fd: RawFd) -> Result<RawFd, LauncherError> {
    if fd >= 10 {
        return Ok(fd);
    }
    let staged = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 10) };
    unsafe { libc::close(fd) };
    if staged < 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(LauncherError::Os("fcntl(F_DUPFD_CLOEXEC, 10)", errno));
    }
    Ok(staged)
}

/// Relocates a staged FD (>= 10) to `target_fd` (6..=9) via `dup3(..., O_CLOEXEC)` and closes the staged FD.
fn relocate_staged_fd(staged_fd: RawFd, target_fd: RawFd) -> Result<(), LauncherError> {
    let ret = unsafe { libc::dup3(staged_fd, target_fd, libc::O_CLOEXEC) };
    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    unsafe { libc::close(staged_fd) };
    if ret < 0 {
        return Err(LauncherError::Os("dup3(pdeath)", errno));
    }
    Ok(())
}

/// Creates the two pipe pairs used for the two-way parent-death synchronization handshake,
/// deterministically mapped to file descriptors 6, 7, 8, and 9 without clobbering `signalfd` (>= 10).
pub fn create_pdeath_pipes() -> Result<(PdeathLauncher, PdeathChild), LauncherError> {
    let mut c2l = [-1; 2];
    if unsafe { libc::pipe2(c2l.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        return Err(LauncherError::Os("pipe2(c2l)", errno));
    }

    let s_c2l_r = match stage_above_9(c2l[0]) {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { libc::close(c2l[1]) };
            return Err(e);
        }
    };
    let s_c2l_w = match stage_above_9(c2l[1]) {
        Ok(fd) => fd,
        Err(e) => {
            unsafe { libc::close(s_c2l_r) };
            return Err(e);
        }
    };

    let mut l2c = [-1; 2];
    if unsafe { libc::pipe2(l2c.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        unsafe {
            libc::close(s_c2l_r);
            libc::close(s_c2l_w);
        }
        return Err(LauncherError::Os("pipe2(l2c)", errno));
    }

    let s_l2c_r = match stage_above_9(l2c[0]) {
        Ok(fd) => fd,
        Err(e) => {
            unsafe {
                libc::close(s_c2l_r);
                libc::close(s_c2l_w);
                libc::close(l2c[1]);
            }
            return Err(e);
        }
    };
    let s_l2c_w = match stage_above_9(l2c[1]) {
        Ok(fd) => fd,
        Err(e) => {
            unsafe {
                libc::close(s_c2l_r);
                libc::close(s_c2l_w);
                libc::close(s_l2c_r);
            }
            return Err(e);
        }
    };

    if let Err(e) = relocate_staged_fd(s_c2l_r, FD_C2L_R) {
        unsafe {
            libc::close(s_c2l_w);
            libc::close(s_l2c_r);
            libc::close(s_l2c_w);
        }
        return Err(e);
    }
    if let Err(e) = relocate_staged_fd(s_c2l_w, FD_C2L_W) {
        unsafe {
            libc::close(FD_C2L_R);
            libc::close(s_l2c_r);
            libc::close(s_l2c_w);
        }
        return Err(e);
    }
    if let Err(e) = relocate_staged_fd(s_l2c_r, FD_L2C_R) {
        unsafe {
            libc::close(FD_C2L_R);
            libc::close(FD_C2L_W);
            libc::close(s_l2c_w);
        }
        return Err(e);
    }
    if let Err(e) = relocate_staged_fd(s_l2c_w, FD_L2C_W) {
        unsafe {
            libc::close(FD_C2L_R);
            libc::close(FD_C2L_W);
            libc::close(FD_L2C_R);
        }
        return Err(e);
    }

    let launcher = PdeathLauncher {
        c2l_r: FD_C2L_R,
        l2c_w: FD_L2C_W,
    };

    let child = PdeathChild {
        c2l_w: FD_C2L_W,
        l2c_r: FD_L2C_R,
    };

    Ok((launcher, child))
}

impl PdeathChild {
    /// Closes unused launcher-side pipe ends (FD 6 and FD 9) in child immediately post-fork.
    pub fn close_launcher_ends() {
        unsafe {
            libc::close(FD_C2L_R);
            libc::close(FD_L2C_W);
        }
    }

    fn handshake_round(
        &self,
        req_tok: u8,
        expected_resp: u8,
        pause_before_read: Option<(&PdeathTestHook, PdeathPausePoint)>,
    ) -> Result<(), LauncherError> {
        ensure_sigpipe_ignored()?;
        install_pdeathsig_sigkill()?;

        write_exact_byte(self.c2l_w, req_tok, "pdeath child write")?;

        if let Some((hook, stage)) = pause_before_read {
            hook.trigger(stage)?;
        }

        let mut resp = [0u8; 1];
        let got_byte = read_exact_byte(self.l2c_r, &mut resp, "pdeath child read")?;
        if !got_byte || resp[0] != expected_resp {
            return Err(LauncherError::PdeathSync(format!(
                "Expected continuation token 0x{expected_resp:02x}, received {resp:?} (eof={})",
                !got_byte
            )));
        }

        Ok(())
    }

    /// Stage 1 (early handshake): runs immediately after fork (before mount/rootfs setup).
    /// Keeps pipe descriptors open for Stage 2.
    pub fn early_arm_and_handshake(
        &self,
        test_hook: Option<&PdeathTestHook>,
    ) -> Result<(), LauncherError> {
        let pause = test_hook.map(|h| (h, PdeathPausePoint::BeforeEarlyContinue));
        let res = self.handshake_round(TOKEN_EARLY_ARMED, TOKEN_EARLY_CONTINUE, pause);
        if res.is_err() {
            unsafe {
                libc::close(self.c2l_w);
                libc::close(self.l2c_r);
            }
        }
        res
    }

    /// Stage 2 (authoritative post-credential/capability handshake): re-arms `PR_SET_PDEATHSIG`,
    /// exchanges final tokens, and closes both child pipe descriptors.
    pub fn arm_and_handshake(self) -> Result<(), LauncherError> {
        let res = self.handshake_round(TOKEN_ARMED, TOKEN_CONTINUE, None);
        unsafe {
            libc::close(self.c2l_w);
            libc::close(self.l2c_r);
        }
        res
    }
}

impl PdeathLauncher {
    /// Closes unused child-side pipe ends (FD 7 and FD 8) in launcher immediately post-fork.
    pub fn close_child_ends() {
        unsafe {
            libc::close(FD_C2L_W);
            libc::close(FD_L2C_R);
        }
    }

    fn handshake_stage(
        &self,
        sfd: RawFd,
        child_pid: libc::pid_t,
        expected_req: u8,
        resp_tok: u8,
        pause_before_reply: Option<(&PdeathTestHook, PdeathPausePoint)>,
    ) -> Result<HandshakeOutcome, LauncherError> {
        ensure_sigpipe_ignored()?;

        let mut poll_fds = [
            libc::pollfd {
                fd: self.c2l_r,
                events: libc::POLLIN | libc::POLLERR | libc::POLLHUP,
                revents: 0,
            },
            libc::pollfd {
                fd: sfd,
                events: libc::POLLIN | libc::POLLERR | libc::POLLHUP,
                revents: 0,
            },
        ];

        loop {
            poll_fds[0].revents = 0;
            poll_fds[1].revents = 0;

            let ret = unsafe { libc::poll(poll_fds.as_mut_ptr(), 2, -1) };
            if ret < 0 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if errno == libc::EINTR {
                    continue;
                }
                return Err(LauncherError::Os("poll(pdeath_handshake)", errno));
            }

            if (poll_fds[1].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)) != 0 {
                return Err(LauncherError::PdeathSync(format!(
                    "signalfd poll error during handshake: revents=0x{:x}",
                    poll_fds[1].revents
                )));
            }

            if (poll_fds[1].revents & libc::POLLIN) != 0 {
                let mut fdsi: libc::signalfd_siginfo = unsafe { mem::zeroed() };
                let sz = mem::size_of::<libc::signalfd_siginfo>();
                let n = unsafe { libc::read(sfd, &mut fdsi as *mut _ as *mut libc::c_void, sz) };
                if n == sz as isize {
                    let signo = fdsi.ssi_signo as i32;
                    if signo == libc::SIGTERM || signo == libc::SIGINT {
                        unsafe { libc::kill(child_pid, signo) };
                    } else if signo == libc::SIGCHLD {
                        let mut status: libc::c_int = 0;
                        let res = unsafe { libc::waitpid(child_pid, &mut status, libc::WNOHANG) };
                        if res == child_pid {
                            return Ok(HandshakeOutcome::ChildTerminated(Some(status)));
                        }
                    }
                } else if n < 0 {
                    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                    if errno != libc::EAGAIN && errno != libc::EINTR {
                        return Err(LauncherError::Os("read(signalfd in handshake)", errno));
                    }
                }
            }

            let pipe_revents = poll_fds[0].revents;
            if (pipe_revents & (libc::POLLERR | libc::POLLNVAL)) != 0 {
                return Err(LauncherError::PdeathSync(format!(
                    "pdeath c2l_r poll error: revents=0x{pipe_revents:x}"
                )));
            }

            if (pipe_revents & libc::POLLIN) != 0 {
                let mut token = [0u8; 1];
                let got_byte = read_exact_byte(self.c2l_r, &mut token, "pdeath launcher read")?;
                if !got_byte {
                    return Ok(HandshakeOutcome::ChildTerminated(None));
                }
                if token[0] != expected_req {
                    return Err(LauncherError::PdeathSync(format!(
                        "Expected handshake token 0x{expected_req:02x}, received 0x{:02x}",
                        token[0]
                    )));
                }

                if let Some((hook, stage)) = pause_before_reply {
                    hook.trigger(stage)?;
                }

                let buf = [resp_tok];
                loop {
                    let written =
                        unsafe { libc::write(self.l2c_w, buf.as_ptr() as *const libc::c_void, 1) };
                    if written == 1 {
                        return Ok(HandshakeOutcome::Completed);
                    }
                    if written < 0 {
                        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                        if errno == libc::EINTR {
                            continue;
                        }
                        if errno == libc::EPIPE {
                            return Ok(HandshakeOutcome::ChildTerminated(None));
                        }
                        return Err(LauncherError::PdeathSync(format!(
                            "Failed to write handshake continuation token: errno {errno}"
                        )));
                    }
                    return Err(LauncherError::PdeathSync(format!(
                        "Unexpected write return during handshake: {written}"
                    )));
                }
            }

            if (pipe_revents & libc::POLLHUP) != 0 {
                return Ok(HandshakeOutcome::ChildTerminated(None));
            }
        }
    }

    /// Stage 1 launcher handshake (`TOKEN_EARLY_ARMED` -> `TOKEN_EARLY_CONTINUE`).
    /// Keeps pipe descriptors open for Stage 2 unless child terminated.
    pub fn handshake_early(
        &self,
        sfd: RawFd,
        child_pid: libc::pid_t,
        test_hook: Option<&PdeathTestHook>,
    ) -> Result<HandshakeOutcome, LauncherError> {
        let pause = test_hook.map(|h| (h, PdeathPausePoint::LauncherBeforeEarlyContinue));
        let outcome = self.handshake_stage(
            sfd,
            child_pid,
            TOKEN_EARLY_ARMED,
            TOKEN_EARLY_CONTINUE,
            pause,
        )?;
        if matches!(outcome, HandshakeOutcome::ChildTerminated(_)) {
            unsafe {
                libc::close(self.c2l_r);
                libc::close(self.l2c_w);
            }
        }
        Ok(outcome)
    }

    /// Stage 2 final launcher handshake (`TOKEN_ARMED` -> `TOKEN_CONTINUE`), closing both descriptors.
    pub fn handshake(
        self,
        sfd: RawFd,
        child_pid: libc::pid_t,
        test_hook: Option<&PdeathTestHook>,
    ) -> Result<HandshakeOutcome, LauncherError> {
        let pause = test_hook.map(|h| (h, PdeathPausePoint::LauncherBeforeFinalContinue));
        let res = self.handshake_stage(sfd, child_pid, TOKEN_ARMED, TOKEN_CONTINUE, pause);
        unsafe {
            libc::close(self.c2l_r);
            libc::close(self.l2c_w);
        }
        res
    }
}
