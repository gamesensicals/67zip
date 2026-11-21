//! The sandboxed worker process of 67zip.
//!
//! The GUI never parses archives itself. It starts a worker process
//! (`67zip --worker`), sends one request as a JSON line on stdin, and reads
//! events (progress, questions, the result) as JSON lines from stdout. Before
//! the worker touches any archive it locks itself down with Landlock (only
//! the files and folders of this request are reachable) and seccomp (no
//! network, no running programs, no debugging other processes).

#![forbid(unsafe_code)]

pub mod client;
pub mod protocol;
pub mod sandbox;
pub mod server;
