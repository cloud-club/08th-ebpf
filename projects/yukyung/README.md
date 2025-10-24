<h2 align="center">eBPF Router</h2>

<p align="center">
  <img src="https://img.shields.io/badge/Go-00ADD8?style=for-the-badge&logo=go&logoColor=white" />
  <img src="https://img.shields.io/badge/eBPF-000000?style=for-the-badge&logoColor=white" />
  <img src="https://img.shields.io/badge/Clang-262D3A?style=for-the-badge&logo=llvm&logoColor=white" />
  <img src="https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black" />
</p>

<p align="center">
  <em>
    eBPF Router는 커널 레벨에서 동작하는 네트워크 패킷 필터링 및 라우팅 시스템입니다.<br>
    XDP(eXpress Data Path)를 활용해 패킷을 실시간으로 분석하고,<br>
    사용자 정의 규칙에 따라 <b>DROP / PASS / REDIRECT</b> 동작을 수행합니다.
  </em>
</p>

<p align="center">
  <img src="https://github.com/user-attachments/assets/89dedf6c-fd87-40cc-af8e-2d4b5c9e28d0" alt="eBPF_example" width="800" />
</p>

<br>

```mermaid
sequenceDiagram
    participant User
    participant App as Go App
    participant Config as config.yaml
    participant Kernel
    participant XDP as eBPF Program
    participant Packet

    User->>App: sudo ./ebpf-router --config config.yaml
    App->>Config: Load & parse rules
    App->>App: Compile eBPF program
    App->>Kernel: Attach XDP to interface
    Kernel->>XDP: Load eBPF program
    XDP-->>App: Ready

    Note over User,Config: 실시간 업데이트
    User->>Config: Edit config.yaml
    App->>Config: Detect change (5s)
    App->>Kernel: Update rules in maps

    Packet->>XDP: Incoming packet
    XDP->>XDP: Parse & match rules
    alt DROP
        XDP->>Kernel: XDP_DROP
    else PASS  
        XDP->>Kernel: XDP_PASS
    else REDIRECT
        XDP->>Kernel: bpf_redirect()
    end
    XDP->>XDP: Update stats

    User->>App: Ctrl+C
    App->>Kernel: Detach XDP
    Kernel-->>App: Unloaded
    App-->>User: Terminated
```
