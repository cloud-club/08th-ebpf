# eBPF uprobe

사용자 공간(user-space) 프로그램의 특정 지점에 동적으로 trace check point를 구성할 수 있도록 해주는것. 프로그램의 수정이나 컴파일 없이 특정 함수가 호출될 때마다 원하는 코드를 실행할 수 있도록 해줌.

## uprobe와 kprobe의 차이

- kprobe: 커널 함수를 추적 (예: sys_read, tcp_sendmsg)
- uprobe: 사용자 프로그램의 함수를 추적 (예: malloc, prinf 등)

## 작동 원리


1. 대상 바이너리 파일에서 함수의 주소를 찾음
2. 해당 주소에 브레이크포인트 명령(INT3)을 삽입
3. 함수가 호출되면 CPU가 트랩 발생
4. eBPF 프로그램이 실행됨
5. 원래 명령을 실행하고 프로그램 계속 진행

### uprobe 와 uretprobe

- uprobe (entry probe)

  - 함수의 시작 지점에 인스톨
  - 함수 인자를 읽을 수 있음
  - 함수 호출 전 직전 상태 관찰
- uretprobe (return probe)

  - 함수의 반환 지점에 구성
  - 함수의 반환값을 읽을 수 있음
  - 함수 실행 시간 측정 가능
