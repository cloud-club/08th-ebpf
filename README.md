# 08th-ebpf
eBPF 스터디 - 커널 모니터링하기 대작전

# 1️⃣ 주제

> 어떤 스터디/프로젝트를 진행하고 싶은지 설명해 주세요!
> 

### 스터디 소개

> 최대한 간단한 스터디를 해보자!
> 
- eBPF로 커널 레벨의 정보를 가져와 서 뭔가 작디작은 것이더라도 해보고 싶은 분들 같이 으쌰으쌰해서 만들어봐요~
    - 저는 간단하게 prometheus exporter를 만들 것 같아요! profiler여도 좋고 pcap sniffer도 좋고 생각나는건 뭐든 좋습니다!
- eBPF 원리부터 필요한 부분을 간단하게 짚고 넘어가고 product 만드는 것에 집중하는 프로젝트 겸 스터디입니다!
- eBPF 자체가 어렵다기보단, syscall/네트워크 레이어의 구조에 맞게 따오는 과정이 커널을 이해해야 해서 어려울 수 있습니다. AI 등을 사용해서 속도감 있게 진행해도 좋지만 결과물에 대해 어떻게 커널의 특정 부분을 따올 수 있었는지 이해할 수 있었으면 좋겠어요!

### 스터디 자료

[eBPF Docs](https://docs.ebpf.io/)

[GitHub - iovisor/bcc: BCC - Tools for BPF-based Linux IO analysis, networking, monitoring, and more](https://github.com/iovisor/bcc)

### 스터디 시간 및 장소

시간: 매주 목요일 오후 8시

장소: 강남교보타워 10층 A동 당근오피스 (그 외 장소제공도 환영입니다~)

[map.naver.com](https://map.naver.com/p/entry/place/21102983?c=15.00,0,0,0,dh&placePath=/home?from=map&fromPanelNum=1&additionalHeight=76&timestamp=202509052158&locale=ko&svcName=map_pcv5)

**OT와 마지막 결과 공유는 오프라인으로 진행하고, 그 외는 온라인/오프라인 병행**

# 2️⃣ 대상

> 어떤 사람이 이 스터디/프로젝트를 따라오기 적절한지 알려주세요!
> 
- 스터디에 시간투자를 많이 하는건 어렵지만 작은 결과물이라도 뽑고자 하는 분
- 애플리케이션으로 커널 관련 정보를 사용해보고 싶었던 분
- eBPF가 궁금한 분
- 옵저버빌리티 툴을 만들어보고 싶은 분

# 3️⃣ 커리큘럼

| 주차 | 주제 | 세부 내용 |
| --- | --- | --- |
| Week 1 |  | OT, BPF 소개 및 개발환경 세팅, bpftrace |
| Week 2 |  | BPF 데이터 타입 및 CO-RE, 데이터 당겨오는 원리 스터디 |
| Week 3 |  | 써보고 싶은 hook이나 syscall 찾아와서 공유하기 |
| Week 4 |  | 해당 정보를 터미널에서 (tc, bpftrace, etc.) 간단하게 끌어온 내용 공유하기 |
| Week 5 & 6 |  | python bcc로 kernel space의 데이터를 user space로 올리기 (스터디 시간동안 개발 진행, 트러블슈팅을 오래할 수도 있어서 같이 보면서 진행하면 좋을 것 같아 이렇게 진행해요) |
| Week 7 |  | kernel space 정보 가져와서 붙여보기 (스터디 시간동안 개발 진행) |
| Week 8 |  | 결과물 공유 |

# 4️⃣ 방식

> 이 스터디/프로젝트만의 규칙이나 진행 방식을 설명해 주세요.
> 

<aside>
🗣️

### 소통

- 슬랙 채널으로 소통해요.
- 미팅은 오프라인/온라인 병행으로 진행하고, 온라인은 google meet으로 참여해요.
</aside>

<aside>
✅

### 규칙

- 초반 공부하는 내용은 각자 공부해오는 내용을 스터디 레포의 `/study/week{num}`에 `{name}.md` 로 작성해요.
- 이후 eBPF 프로젝트는 `/project/{name}/`에 추가해요.
    - 모노레포 방식이라 fast forward가 많이 발생할 수도 있어 force push는 허용해둘게요. 다만 남의 기록 날리지 않도록 주의!
    - PR 없이 알아서 main push 해주세요~
</aside>

<aside>
❓

### 질문

- 자유롭게 작성해주시면 답변할게요~
</aside>

# 5️⃣ 기록

> 클클 GitHub를 활용해서 스터디/프로젝트를 기록해주세요. 외부 저장소를 사용할 경우 링크를 남겨주세요.
> 

<aside>
🗃️

**8기 클둥이를 위해 좋은 레퍼런스를 클클 GitHub의 template 레포지토리에 모아뒀어요!** 

**→ [template repository link](https://github.com/cloud-club/template)**
📢 **스터디 리더님의 적극적인 관리가 동아리의 성장과 지속가능성에 큰 도움을 줍니다!** 🚀

모두가 함께 배우고 성장할 수 있도록 GitHub Repository를 잘 운영해 주시면 감사하겠습니다.
(+스터디 마무리 후, 관리가 잘 된 스터디의 repo는 클라우드 클럽의 홍보자료로도 사용될 수 있습니다!

</aside>

[GitHub - cloud-club/08th-ebpf: eBPF 스터디 - 커널 모니터링하기 대작전](https://github.com/cloud-club/08th-ebpf)

# **6️⃣ 출석부**

> 3회 이상 불참 시 8기를 수료할 수 없어요.
> 

|  | 1주차 | 2주차 | 3주차 | 4주차 | 5주차 | 6주차 | 7주차 | 8주차 |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 최용환 |  |  |  |  |  |  |  |  |
| 김유경 |  |  |  |  |  |  |  |  |
| 유승훈 |  |  |  |  |  |  |  |  |
| 김재훈 |  |  |  |  |  |  |  |  |
| 문영호 |  |  |  |  |  |  |  |  |
| 권민정 |  |  |  |  |  |  |  |  |
| 이장원 |  |  |  |  |  |  |  |  |
| 윤서율 |  |  |  |  |  |  |  |  |
| 임예준 |  |  |  |  |  |  |  |  |
| 김예지 |  |  |  |  |  |  |  |  |