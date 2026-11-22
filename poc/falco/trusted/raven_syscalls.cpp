#include "raven_syscalls.hpp"
#include <arpa/inet.h>
#include <cstring>

void RavenSyscalls::seed_from_snapshot(const sinsp& inspector) {
    // libsinsp has already applied a successful setuid when translate() sees its exit.
    inspector.m_thread_manager->get_threads()->const_loop([this](const sinsp_threadinfo& thread) {
        if (thread.is_main_thread() && thread.m_pid > 0 && thread.m_uid != UINT32_MAX)
            effective_uids.emplace(thread.m_pid, thread.m_uid);
        return true;
    });
}

rz::Json RavenSyscalls::translate(sinsp_evt& evt, uint32_t collector_pid) {
    auto* thread = evt.get_thread_info();
    if (!thread || thread->m_pid <= 0) return nullptr;
    const auto type = evt.get_type();
    const auto pid = thread->m_pid;
    const auto uid = thread->m_uid;
    auto previous = effective_uids.find(pid);
    const auto old_uid = previous == effective_uids.end() ? uid : previous->second;
    effective_uids[pid] = uid;

    rz::Json row = nullptr;
    switch (type) {
    case PPME_SYSCALL_EXECVE_19_X:
    case PPME_SYSCALL_EXECVEAT_X:
        if (evt.get_syscall_return_value() < 0) return nullptr;
        row["event_type"] = "process_exec";
        row["args"] = thread->m_args;
        break;
    case PPME_SYSCALL_CLONE_20_X:
    case PPME_SYSCALL_CLONE3_X:
    case PPME_SYSCALL_FORK_20_X:
    case PPME_SYSCALL_VFORK_20_X:
        // The child's exit record carries its own PID and parent. Ignore the parent's copy.
        if (evt.get_syscall_return_value() != 0 || !thread->is_main_thread()) return nullptr;
        row["event_type"] = "process_fork";
        break;
    case PPME_PROCEXIT_1_E:
        if (!thread->is_main_thread()) return nullptr;
        effective_uids.erase(pid);
        row["event_type"] = "process_exit";
        break;
    case PPME_SOCKET_CONNECT_X: {
        auto res = evt.get_syscall_return_value();
        if (res != 0 && res != -EINPROGRESS) return nullptr;
        const auto* addr = evt.get_param_by_name("addr");
        if (!addr || addr->empty()) return nullptr;
        int family = static_cast<unsigned char>(addr->data()[0]);
        size_t bytes = family == PPM_AF_INET ? 4 : family == PPM_AF_INET6 ? 16 : 0;
        if (!bytes || addr->len() < 1 + bytes + sizeof(uint16_t)) return nullptr;
        char ip[INET6_ADDRSTRLEN]{};
        if (!inet_ntop(bytes == 4 ? AF_INET : AF_INET6, addr->data()+1, ip, sizeof(ip))) return nullptr;
        uint16_t port;
        std::memcpy(&port, addr->data()+1+bytes, sizeof(port));
        row = {{"event_type","net_connect"},{"dst_ip",ip},{"dst_port",port}};
        break;
    }
    case PPME_SOCKET_LISTEN_X: {
        const auto* fd = evt.get_fd_info();
        if (evt.get_syscall_return_value() != 0 || !fd) return nullptr;
        uint16_t port;
        if (fd->m_type == SCAP_FD_IPV4_SERVSOCK) port = fd->m_sockinfo.m_ipv4serverinfo.m_port;
        else if (fd->m_type == SCAP_FD_IPV6_SERVSOCK) port = fd->m_sockinfo.m_ipv6serverinfo.m_port;
        else return nullptr;
        row = {{"event_type","net_listen"},{"dst_port",port}};
        break;
    }
    case PPME_SYSCALL_OPEN_X:
    case PPME_SYSCALL_OPENAT_2_X:
    case PPME_SYSCALL_OPENAT2_X:
    case PPME_SYSCALL_CREAT_X: {
        const auto* fd = evt.get_fd_info();
        if (evt.get_syscall_return_value() < 0 || !fd || !fd->is_file()) return nullptr;
        const auto* flags = evt.get_param_by_name("flags");
        bool create = type == PPME_SYSCALL_CREAT_X ||
                      (flags && (flags->as<uint32_t>() & (PPM_O_F_CREATED | PPM_O_TRUNC)));
        row = {{"event_type",create ? "file_modify" : "file_access"},{"file_path",fd->m_name},
               {"file_op",create ? "create" : "open"}};
        auto* mode = evt.get_param_by_name("mode");
        if (create && mode && (mode->as<uint32_t>() & 0111)) row["metadata"]["created_executable"] = true;
        break;
    }
    case PPME_SYSCALL_WRITE_X:
    case PPME_SYSCALL_PWRITE_X:
    case PPME_SYSCALL_WRITEV_X:
    case PPME_SYSCALL_PWRITEV_X: {
        const auto* fd = evt.get_fd_info();
        // Recording an input or emitting an alert must not generate the next recorded input.
        if (pid == collector_pid || evt.get_syscall_return_value() <= 0 || !fd || !fd->is_file()) return nullptr;
        row = {{"event_type","file_modify"},{"file_path",fd->m_name},{"file_op","write"}};
        break;
    }
    case PPME_SYSCALL_CHMOD_X:
    case PPME_SYSCALL_FCHMOD_X:
    case PPME_SYSCALL_FCHMODAT_X: {
        if (evt.get_syscall_return_value() != 0 || !(evt.get_param_by_name("mode")->as<uint32_t>() & 0111))
            return nullptr;
        const auto* fd = evt.get_fd_info();
        if (type == PPME_SYSCALL_FCHMOD_X && !fd) return nullptr;
        auto path = type == PPME_SYSCALL_FCHMOD_X ? fd->m_name : evt.get_param_value_str("filename");
        if (path.empty()) return nullptr;
        row = {{"event_type","file_modify"},{"file_path",path},{"file_op","chmod"},
               {"metadata",{{"created_executable",true}}}};
        break;
    }
    case PPME_SYSCALL_SETUID_X:
    case PPME_SYSCALL_SETRESUID_X:
    case PPME_SYSCALL_SETREUID_X:
        if (evt.get_syscall_return_value() != 0 || old_uid == uid || old_uid == UINT32_MAX || uid == UINT32_MAX)
            return nullptr;
        row = {{"event_type","privilege_change"},{"uid",old_uid}};
        break;
    default:
        return nullptr;
    }
    auto* main = thread->get_main_thread();
    auto parent_tid = main ? main->m_ptid : thread->m_ptid;
    const auto& parent = evt.get_inspector()->m_thread_manager->find_thread(parent_tid, true);
    row["pid"] = pid;
    row["ppid"] = parent ? parent->m_pid : parent_tid;
    row["ts"] = double(evt.get_ts()) / 1e9;
    row["event_id"] = "ring-" + std::to_string(evt.get_num());
    row["exe"] = thread->m_exepath;
    row["exe_name"] = thread->m_comm;
    if (!row.contains("uid")) row["uid"] = uid;
    row["euid"] = uid;
    row["user"] = std::to_string(uid);
    return row;
}
