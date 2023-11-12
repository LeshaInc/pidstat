use std::alloc::Layout;
use std::ffi::CStr;
use std::fs::File;
use std::mem::size_of;
use std::os::fd::AsRawFd;
use std::path::Path;
use std::ptr;
use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use libc::pid_t;
use nix::errno::Errno;
use nix::request_code_read;
use nix::{ioctl_read, ioctl_write_ptr};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ProcessInfo {
    pub pid: pid_t,
    pub ppid: pid_t,
    pub pgid: pid_t,
    pub sid: pid_t,
    pub vss: u64,
    pub rss: u64,
    pub tasks: Vec<TaskInfo>,
}

#[repr(C)]
#[derive(Debug)]
struct RawProcessInfo<Tasks: ?Sized = [RawTaskInfo]> {
    pid: pid_t,
    ppid: pid_t,
    pgid: pid_t,
    sid: pid_t,
    vss: u64,
    rss: u64,
    num_tasks: usize,
    tasks: Tasks,
}

impl ProcessInfo {
    pub fn from_pid(pid: pid_t) -> Result<Option<Self>> {
        get_process_info(pid)
    }

    fn from_raw(raw: &RawProcessInfo) -> Result<Self> {
        Ok(Self {
            pid: raw.pid,
            ppid: raw.ppid,
            pgid: raw.pgid,
            sid: raw.sid,
            vss: raw.vss,
            rss: raw.rss,
            tasks: raw
                .tasks
                .iter()
                .map(TaskInfo::from_raw)
                .collect::<Result<Vec<_>>>()?,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TaskInfo {
    pub tid: pid_t,
    pub state: TaskState,
    pub command: String,
    pub utime: Duration,
    pub stime: Duration,
    pub start_time: Duration,
    pub min_flt: u64,
    pub maj_flt: u64,
    pub prio: i32,
    pub nice: i32,
    pub cpu: u32,
}

#[repr(C)]
#[derive(Debug)]
struct RawTaskInfo {
    tid: pid_t,
    state: TaskState,
    command: [u8; 16],
    utime_ns: u64,
    stime_ns: u64,
    start_time_ns: u64,
    min_flt: u64,
    maj_flt: u64,
    prio: i32,
    nice: i32,
    cpu: u32,
}

#[repr(u8)]
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Serialize)]
pub enum TaskState {
    Running,
    Sleeping,
    DiskSleep,
    Stopped,
    TracingStop,
    Dead,
    Zombie,
    Parked,
    Idle,
}

impl TaskInfo {
    fn from_raw(raw: &RawTaskInfo) -> Result<Self> {
        Ok(Self {
            tid: raw.tid,
            state: raw.state,
            command: CStr::from_bytes_until_nul(&raw.command)?
                .to_string_lossy()
                .into_owned(),
            utime: Duration::from_nanos(raw.utime_ns),
            stime: Duration::from_nanos(raw.stime_ns),
            start_time: Duration::from_nanos(raw.start_time_ns),
            min_flt: raw.min_flt,
            maj_flt: raw.maj_flt,
            prio: raw.prio,
            nice: raw.nice,
            cpu: raw.cpu,
        })
    }
}

fn get_process_info(pid: pid_t) -> Result<Option<ProcessInfo>> {
    ioctl_write_ptr!(pidstat_write_tid, 'a', 1, pid_t);
    ioctl_read!(pidstat_read_num_tasks, 'a', 2, usize);
    const RD_PSTAT: u64 = request_code_read!('a', 3, size_of::<RawProcessInfo<[RawTaskInfo; 0]>>());

    let path = Path::new("/dev/pidstat");
    let file = File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;
    let fd = file.as_raw_fd();

    let raw = unsafe {
        let res = pidstat_write_tid(fd, &pid);

        if res.is_err_and(|e| e == Errno::ENOENT) {
            return Ok(None);
        }

        res.context("ioctl call failed")?;

        let mut num_tasks = 0;
        pidstat_read_num_tasks(fd, &mut num_tasks).context("ioctl call failed")?;

        let (layout, _) = Layout::new::<RawProcessInfo<[RawTaskInfo; 0]>>()
            .extend(Layout::array::<RawTaskInfo>(num_tasks).unwrap())
            .unwrap();
        let layout = layout.pad_to_align();
        let ptr = std::alloc::alloc(layout);
        if ptr.is_null() {
            std::alloc::handle_alloc_error(layout);
        }

        Errno::result(libc::ioctl(fd, RD_PSTAT, ptr)).context("ioctl call failed")?;

        let fake_fat_ptr: *mut [RawProcessInfo<RawTaskInfo>] =
            ptr::slice_from_raw_parts_mut(ptr.cast(), num_tasks);
        Box::<RawProcessInfo>::from_raw(fake_fat_ptr as _)
    };

    ProcessInfo::from_raw(&raw).map(Some)
}
