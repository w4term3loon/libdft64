use std::{
    env, path::PathBuf, fs, process::{Command, Stdio}, path::Path, os::unix::fs::symlink, fs::OpenOptions, os::fd::AsRawFd, os::unix::{io::RawFd, process::CommandExt},  
};

use libc;
use log::{warn, error};

use clap::{Arg, Command as argCommand};

static TMP_DIR: &str = "tmp";
static INPUT_FILE: &str = "cur_input";
static FORKSRV_SOCKET_FILE: &str = "forksrv_socket";
static TRACK_FILE: &str = "track";
static PIN_ROOT_VAR: &str = "PIN_ROOT";

static PERSIST_TRACK_FILES: &str = "DISABLE_TMPFS";
static LINUX_TMPFS_DIR: &str = "/dev/shm";

pub trait SetLimit {
    fn mem_limit(&mut self, size: u64) -> &mut Self;
    fn setsid(&mut self) -> &mut Self;
    fn pipe_stdin(&mut self, fd: RawFd, is_stdin: bool) -> &mut Self;
    //fn dup2(&mut self, src: libc::c_int, dst: libc::c_int) -> &mut Self;
    //fn close_fd(&mut self, fd: libc::c_int) -> &mut Self;
}
impl SetLimit for Command {
    fn mem_limit(&mut self, size: u64) -> &mut Self {
        if size == 0 {
            return self;
        }

        let func = move || {
            let size = size << 20;
            let mem_limit: libc::rlim_t = size;
            let r = libc::rlimit {
                rlim_cur: mem_limit,
                rlim_max: mem_limit,
            };

            let r0 = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };

            unsafe {
                libc::setrlimit(libc::RLIMIT_AS, &r);
                // libc::setrlimit(libc::RLIMIT_DATA, &r);
                libc::setrlimit(libc::RLIMIT_CORE, &r0);
            };

            Ok(())
        };

        unsafe { self.pre_exec(func) }
    }

    fn setsid(&mut self) -> &mut Self {
        let func = move || {
            unsafe {
                libc::setsid();
            };
            Ok(())
        };
        unsafe { self.pre_exec(func) }
    }

    fn pipe_stdin(&mut self, fd: RawFd, is_stdin: bool) -> &mut Self {
        if is_stdin {
            let func = move || {
                let ret = unsafe { libc::dup2(fd, libc::STDIN_FILENO) };
                if ret < 0 {
                    panic!("dup2() failded");
                }
                unsafe {
                    libc::close(fd);
                }
                Ok(())
            };
            unsafe { self.pre_exec(func) }
        } else {
            self
        }
    }
}

pub fn filter_args() -> Vec<String> {
    let mut args = vec![env::args().next().unwrap()];
    let mut args_iter = env::args();
    let mut i = 0;
    let mut parg = vec![];
    while let Some(arg) = args_iter.next() {
        if arg.starts_with("--") {
            args.push(arg);
            args.push(args_iter.next().unwrap());
        } else if arg.starts_with("-") {
            args.push(arg);
            args.push(args_iter.next().unwrap());
        }
        else{
            if i > 0 {
                while let Some(arg) = args_iter.next(){
                    parg.push(arg);
                }
                args.extend(parg.clone());
            }
        }
        i = i + 2;
    }
    args
}

pub fn main(){
    // get args
    let res = match argCommand::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author("Taintfuzzer")
        .about("LibAFL-based fuzzer with libdft64")
        .arg(
            Arg::new("in")
                .help("The directory to read initial inputs from ('seeds')")
                .long("libafl-in")
                .short('i')
                .required(true),
        )
        .arg(
            Arg::new("out")
                .help("The directory to place finds in ('corpus')")
                .short('o')
                .long("libafl-out")
                .required(true),
        )
        .arg(
            Arg::new("taint")
                .long("libdft-taint")
                .short('t')
                .help("A file to read tokens from, to be used during fuzzing")
                .required(true),
        )
        .arg(Arg::new("pargs")
            .help("Targeted program (USE_FAST) and arguments. Any \"@@\" will be substituted with the input filename from Angora.")
            .allow_hyphen_values(true)
            .last(true)
            .index(1)
        )
        .try_get_matches_from(filter_args())
    {
        Ok(res) => res,
        Err(err) => {
            println!(
                "Syntax: {} -i <input> -o <output> -- <program>\n{:?}",
                env::current_exe()
                    .unwrap_or_else(|_| "fuzzer".into())
                    .to_string_lossy(),
                err,
            );
            return;
        }
    };

    // set params
    let mut out_dir = PathBuf::from(res.get_one::<String>("out").unwrap().to_string());
    if fs::create_dir(&out_dir).is_err() {
        println!("Out dir at {:?} already exists.", &out_dir);
        if !out_dir.is_dir() {
            println!("Out dir at {:?} is not a valid directory!", &out_dir);
            return;
        }
    }
    let mut crashes = out_dir.clone();
    crashes.push("crashes");

    let in_dir = PathBuf::from(res.get_one::<String>("in").unwrap().to_string());
    if !in_dir.is_dir() {
        println!("In dir at {:?} is not a valid directory!", &in_dir);
        return;
    }

    let taint = PathBuf::from(res.get_one::<String>("taint").unwrap().to_string());
    if !taint.is_file() {
        println!("Taint at {:?} is not a valid file!", &in_dir);
        return;
    }

    // set pargs
    let mut args_iter = env::args();
    let mut pargs = vec![];
    let mut flag = 0;
    while let Some(arg) = args_iter.next() {
        if flag == 1 {
            pargs.push(arg.clone());
        }
        if arg == "--" {
            flag = 1;
        }
    }

    // fuzz
    fuzz(in_dir, out_dir, taint, pargs);
}


fn fuzz(
    mut in_dir: PathBuf,
    mut out_dir: PathBuf,
    taint: PathBuf,
    mut pargs: Vec<String>,
){
    //set fuzz program and parameters
    let mut track_args = Vec::<String>::new();
    let main_bin = pargs[0].clone();
    let main_args: Vec<String> = pargs.drain(1..).collect();
    
    //set pin tool
    let pin_root = env::var(PIN_ROOT_VAR).expect("You should set the environment of PIN_ROOT!");
    let pin_bin = format!("{}/{}", pin_root, "pin");
    let track_bin = pin_bin.to_string();
    let pin_tool = taint.to_str().unwrap().to_owned();
    
    //set pin tool parameters
    track_args.push(String::from("-t"));
    track_args.push(pin_tool);
    track_args.push(String::from("--"));
    track_args.push(main_bin.to_string());
    track_args.extend(main_args.clone());

    // input fd
    out_dir.push(TMP_DIR);
    let mut tmp_dir = out_dir;
    fs::create_dir(&(tmp_dir.to_str().unwrap().to_owned())).unwrap();
    tmp_dir.push(INPUT_FILE);
    let cur_input = tmp_dir.to_str().unwrap().to_owned();
    let fd = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&cur_input)
        .expect("Fail to open default input file!");


    // is stdin or other input
    let has_input_arg = pargs.contains(&"@@".to_string());
    let is_stdin = !has_input_arg;

    match Command::new(&(main_bin.to_string()))
        .args(&(main_args.clone()))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .pipe_stdin(fd.as_raw_fd(), is_stdin)
        .spawn()
    {
        Ok(_) => (),
        Err(e) => {
            error!("FATAL: Failed to spawn child. Reason: {}", e);
            panic!();
        },
    };

    match Command::new(&(track_bin.to_string()))
        .args(&(track_args.clone()))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .pipe_stdin(fd.as_raw_fd(), is_stdin)
        .spawn()
    {
        Ok(_) => (),
        Err(e) => {
            error!("FATAL: Failed to spawn child. Reason: {}", e);
            panic!();
        },
    };

}