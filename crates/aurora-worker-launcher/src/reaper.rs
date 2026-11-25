//! Signal management via signalfd, startup gate coordination, proxy reaping, and exit mirroring.

use crate::{LauncherError, GATE_CONTINUE, GATE_READY};
use std::fs;
use std::mem;
use std::os::unix::io::RawFd;
use std::path::Path;

pub struct SignalContext {
    sfd: RawFd,
}

impl SignalContext {
    /// Returns the signalfd descriptor (guaranteed >= 10 in the launcher).
    pub fn raw_fd(&self) -> RawFd {
        self.sfd
    }

    /// Blocks SIGTERM, SIGINT, SIGCHLD on the current thread and opens a signalfd
    /// placed at FD >= 10 so it cannot collide with reserved FDs 0..=9.
    pub fn new() -> Result<Self, LauncherError> {
        let mut mask: libc::sigset_t = unsafe { mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut mask);
            libc::sigaddset(&mut mask, libc::SIGTERM);
            libc::sigaddset(&mut mask, libc::SIGINT);
            libc::sigaddset(&mut mask, libc::SIGCHLD);

            let ret = libc::pthread_sigmask(libc::SIG_BLOCK, &mask, std::ptr::null_mut());
            if ret != 0 {
                return Err(LauncherError::Os("pthread_sigmask(SIG_BLOCK)", ret));
            }

            let raw_fd = libc::signalfd(-1, &mask, libc::SFD_NONBLOCK | libc::SFD_CLOEXEC);
            if raw_fd < 0 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                return Err(LauncherError::Os("signalfd", errno));
            }

            let sfd = if raw_fd < 10 {
                let relocated = libc::fcntl(raw_fd, libc::F_DUPFD_CLOEXEC, 10);
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                libc::close(raw_fd);
                if relocated < 0 {
                    return Err(LauncherError::Os(
                        "fcntl(signalfd, F_DUPFD_CLOEXEC, 10)",
                        errno,
                    ));
                }
                relocated
            } else {
                raw_fd
            };

            Ok(Self { sfd })
        }
    }

    /// Closes signalfd, installs pre-exec PID-1 termination handlers for SIGTERM/SIGINT,
    /// and restores unblocked signal mask in the child.
    ///
    /// Why pre-exec PID-1 handler instead of `SIG_DFL` before `execve()`:
    /// The worker child is PID 1 in its private PID namespace, so the Linux kernel sets
    /// `SIGNAL_UNKILLABLE` and silently ignores `SIGTERM`/`SIGINT` when their disposition is
    /// `SIG_DFL`—even when sent from the ancestor launcher. Installing an async-signal-safe
    /// handler (`_exit(128 + sig)`, `sa_flags = 0` without `SA_RESTART`) ensures pre-exec
    /// forwarded `SIGTERM`/`SIGINT` terminates PID 1 promptly, while `execve()` automatically
    /// resets caught signal dispositions back to `SIG_DFL` for the worker binary.
    ///
    /// Intentional SIGPIPE policy: `ensure_sigpipe_ignored()` sets `SIGPIPE` to `SIG_IGN`
    /// through both handshake stages so a dead launcher yields `EPIPE`; `restore_sigpipe_default()`
    /// resets `SIGPIPE` to `SIG_DFL` immediately prior to `execve()`.
    pub fn restore_for_child(self) -> Result<(), LauncherError> {
        extern "C" fn handle_pre_exec_term(sig: libc::c_int) {
            unsafe { libc::_exit(128 + sig) };
        }

        unsafe {
            libc::close(self.sfd);

            // Reset SIGCHLD to default
            if libc::signal(libc::SIGCHLD, libc::SIG_DFL) == libc::SIG_ERR {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                return Err(LauncherError::Os("signal(SIGCHLD, SIG_DFL)", errno));
            }

            // Install pre-exec termination handler (no SA_RESTART) so PID 1 responds to SIGTERM/SIGINT
            let mut sa: libc::sigaction = mem::zeroed();
            sa.sa_sigaction = handle_pre_exec_term as *const () as usize;
            libc::sigemptyset(&mut sa.sa_mask);
            sa.sa_flags = 0;

            for sig in [libc::SIGTERM, libc::SIGINT] {
                if libc::sigaction(sig, &sa, std::ptr::null_mut()) != 0 {
                    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                    return Err(LauncherError::Os("sigaction(SIGTERM/SIGINT)", errno));
                }
            }

            // Unblock all signals so the worker receives standard signal delivery
            let mut empty: libc::sigset_t = mem::zeroed();
            libc::sigemptyset(&mut empty);
            let ret = libc::pthread_sigmask(libc::SIG_SETMASK, &empty, std::ptr::null_mut());
            if ret != 0 {
                return Err(LauncherError::Os("pthread_sigmask(SIG_SETMASK empty)", ret));
            }
        }
        Ok(())
    }

    /// Restores `SIGPIPE` to `SIG_DFL` immediately before `execve()` after handshake completion.
    pub fn restore_sigpipe_default() -> Result<(), LauncherError> {
        let prev = unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
        if prev == libc::SIG_ERR {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            return Err(LauncherError::Os("signal(SIGPIPE, SIG_DFL)", errno));
        }
        Ok(())
    }

    /// Pauses at the startup gate while monitoring signalfd for termination signals.
    ///
    /// If `gate_ready_fd` is provided, writes `GATE_READY` (0x01) and closes it to acknowledge
    /// to the supervisor/test harness that the launcher has reached the gate.
    pub fn wait_at_startup_gate(
        &self,
        gate_fd: Option<RawFd>,
        gate_ready_fd: Option<RawFd>,
        strict_mode: bool,
    ) -> Result<(), LauncherError> {
        if strict_mode && gate_fd.is_none() {
            return Err(LauncherError::CgroupGateMissing(
                "Cgroup startup gate is mandatory in strict mode (--cgroup-gate-fd)".to_string(),
            ));
        }

        // Acknowledge gate readiness if an acknowledgement FD was passed
        if let Some(rfd) = gate_ready_fd {
            let token = [GATE_READY];
            let _ = unsafe { libc::write(rfd, token.as_ptr() as *const libc::c_void, 1) };
            unsafe { libc::close(rfd) };
        }

        let Some(gfd) = gate_fd else {
            return Ok(());
        };

        // Poll both the startup gate FD and the signalfd
        let mut poll_fds = [
            libc::pollfd {
                fd: gfd,
                events: libc::POLLIN | libc::POLLERR | libc::POLLHUP,
                revents: 0,
            },
            libc::pollfd {
                fd: self.sfd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];

        loop {
            let ret = unsafe { libc::poll(poll_fds.as_mut_ptr(), 2, -1) };
            if ret < 0 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if errno == libc::EINTR {
                    continue;
                }
                unsafe { libc::close(gfd) };
                return Err(LauncherError::Os("poll(gate)", errno));
            }

            // Check if a termination signal arrived via signalfd
            if (poll_fds[1].revents & libc::POLLIN) != 0 {
                let mut fdsi: libc::signalfd_siginfo = unsafe { mem::zeroed() };
                let sz = mem::size_of::<libc::signalfd_siginfo>();
                let n =
                    unsafe { libc::read(self.sfd, &mut fdsi as *mut _ as *mut libc::c_void, sz) };
                if n == sz as isize {
                    let signo = fdsi.ssi_signo as i32;
                    if signo == libc::SIGTERM || signo == libc::SIGINT {
                        unsafe { libc::close(gfd) };
                        return Err(LauncherError::SignalTerminated(signo));
                    }
                }
            }

            // Check if startup gate has been released
            if (poll_fds[0].revents & libc::POLLIN) != 0 {
                let mut token = [0u8; 1];
                let n = unsafe { libc::read(gfd, token.as_mut_ptr() as *mut libc::c_void, 1) };
                unsafe { libc::close(gfd) };

                if n == 1 && token[0] == GATE_CONTINUE {
                    return Ok(());
                } else {
                    return Err(LauncherError::CgroupGateMissing(format!(
                        "Invalid gate token: expected 0x01, received {token:?}, bytes read: {n}"
                    )));
                }
            }

            if (poll_fds[0].revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL)) != 0 {
                unsafe { libc::close(gfd) };
                return Err(LauncherError::CgroupGateMissing(
                    "Startup gate pipe is invalid or closed before token was received".to_string(),
                ));
            }
        }
    }

    /// Terminates launcher with the exact signal if terminated before fork (e.g. at startup gate).
    pub fn raise_and_exit_signal(self, sig: i32) -> ! {
        unsafe {
            libc::close(self.sfd);
            libc::signal(sig, libc::SIG_DFL);
            let mut unblock: libc::sigset_t = mem::zeroed();
            libc::sigemptyset(&mut unblock);
            libc::sigaddset(&mut unblock, sig);
            libc::pthread_sigmask(libc::SIG_UNBLOCK, &unblock, std::ptr::null_mut());
            libc::raise(sig);
            libc::exit(128 + sig);
        }
    }

    /// Collects child exit status using blocking `waitpid` (retrying `EINTR`) after pipe EOF,
    /// cleans up the host rootfs mountpoint, and mirrors the exact status.
    pub fn reap_blocking_and_mirror(self, child_pid: libc::pid_t, sandbox_host_dir: &Path) -> ! {
        let mut status: libc::c_int = 0;
        loop {
            let res = unsafe { libc::waitpid(child_pid, &mut status, 0) };
            if res == child_pid {
                let _ = fs::remove_dir(sandbox_host_dir);
                self.mirror_exit_status(status);
            }
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if errno == libc::EINTR {
                continue;
            }
            let _ = fs::remove_dir(sandbox_host_dir);
            eprintln!("aurora-worker-launcher: waitpid({child_pid}) failed: errno {errno}");
            unsafe {
                libc::close(self.sfd);
                libc::exit(crate::ERR_PDEATH_FAILED);
            }
        }
    }

    /// Enters the proxy reaping loop, catching signals from the supervisor, forwarding
    /// SIGTERM/SIGINT to the child, cleaning up the host rootfs mountpoint, and mirroring
    /// the child's exact exit status or terminating signal.
    pub fn proxy_reap_and_mirror(self, child_pid: libc::pid_t, sandbox_host_dir: &Path) -> ! {
        let mut poll_fds = [libc::pollfd {
            fd: self.sfd,
            events: libc::POLLIN | libc::POLLERR | libc::POLLHUP,
            revents: 0,
        }];

        loop {
            // First check if child has already exited
            let mut status: libc::c_int = 0;
            let res = unsafe { libc::waitpid(child_pid, &mut status, libc::WNOHANG) };
            if res == child_pid {
                let _ = fs::remove_dir(sandbox_host_dir);
                self.mirror_exit_status(status);
            } else if res < 0 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if errno != libc::EINTR {
                    let _ = fs::remove_dir(sandbox_host_dir);
                    eprintln!("aurora-worker-launcher: waitpid failed: errno {errno}");
                    unsafe {
                        libc::close(self.sfd);
                        libc::exit(1);
                    }
                }
            }

            poll_fds[0].revents = 0;

            // Wait indefinitely for signalfd events
            let ret = unsafe { libc::poll(poll_fds.as_mut_ptr(), 1, -1) };
            if ret < 0 {
                let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if errno == libc::EINTR {
                    continue;
                }
                let _ = fs::remove_dir(sandbox_host_dir);
                eprintln!("aurora-worker-launcher: poll(signalfd) failed: errno {errno}");
                unsafe {
                    libc::close(self.sfd);
                    libc::exit(1);
                }
            }

            if (poll_fds[0].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)) != 0 {
                let _ = fs::remove_dir(sandbox_host_dir);
                eprintln!(
                    "aurora-worker-launcher: signalfd poll error: revents=0x{:x}",
                    poll_fds[0].revents
                );
                unsafe {
                    libc::close(self.sfd);
                    libc::exit(1);
                }
            }

            if (poll_fds[0].revents & libc::POLLIN) != 0 {
                let mut fdsi: libc::signalfd_siginfo = unsafe { mem::zeroed() };
                let sz = mem::size_of::<libc::signalfd_siginfo>();
                let n =
                    unsafe { libc::read(self.sfd, &mut fdsi as *mut _ as *mut libc::c_void, sz) };
                if n == sz as isize {
                    let signo = fdsi.ssi_signo as i32;
                    if signo == libc::SIGTERM || signo == libc::SIGINT {
                        // Forward termination signal explicitly to worker child
                        unsafe { libc::kill(child_pid, signo) };
                    } else if signo == libc::SIGCHLD {
                        let res = unsafe { libc::waitpid(child_pid, &mut status, libc::WNOHANG) };
                        if res == child_pid {
                            let _ = fs::remove_dir(sandbox_host_dir);
                            self.mirror_exit_status(status);
                        } else if res < 0 {
                            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                            if errno != libc::EINTR {
                                let _ = fs::remove_dir(sandbox_host_dir);
                                unsafe {
                                    libc::close(self.sfd);
                                    libc::exit(1);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Mirrors the child's exit status:
    /// - Normal exit: exits with WEXITSTATUS.
    /// - Terminated by signal: resets handler, unblocks signal, and raises it.
    pub fn mirror_exit_status(self, status: libc::c_int) -> ! {
        unsafe {
            libc::close(self.sfd);

            if libc::WIFEXITED(status) {
                let code = libc::WEXITSTATUS(status);
                libc::exit(code);
            }

            if libc::WIFSIGNALED(status) {
                let sig = libc::WTERMSIG(status);

                // Reset signal handler to default
                libc::signal(sig, libc::SIG_DFL);

                // Unblock the signal in thread mask
                let mut unblock: libc::sigset_t = mem::zeroed();
                libc::sigemptyset(&mut unblock);
                libc::sigaddset(&mut unblock, sig);
                libc::pthread_sigmask(libc::SIG_UNBLOCK, &unblock, std::ptr::null_mut());

                // Re-raise signal to mirror terminating signal to parent/supervisor
                libc::raise(sig);

                // In case raise returns (e.g. ignored signal)
                libc::exit(128 + sig);
            }

            // Fallback for unexpected exit condition
            libc::exit(1);
        }
    }
}
