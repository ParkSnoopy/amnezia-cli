use std::{
    fs::{
        self,
        OpenOptions,
    },
    io::{
        BufRead,
        BufReader,
        Write as _,
    },
    net::{
        TcpListener,
        TcpStream,
    },
    os::unix::ffi::OsStringExt,
    path::{
        Path,
        PathBuf,
    },
    process::{
        Command,
        Stdio,
    },
};

use anyhow::{
    Context,
    Result,
    anyhow,
    bail,
};

use crate::core::{
    model::{
        Connection,
        Profile,
        Protocol,
        Settings,
        State,
        XrayRouteIdentity,
    },
    store::Store,
    transaction::{QuickDirection, QuickProgram, ReversibleMutation},
};


include!("executor/quick.rs");
include!("executor/openvpn.rs");
include!("executor/xray.rs");
include!("executor/lifecycle.rs");
include!("executor/tests.rs");
