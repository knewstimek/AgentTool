# agent-tool

[English](README.md)

<a href="https://glama.ai/mcp/servers/knewstimek/agent-tool">
  <img width="380" height="200" src="https://glama.ai/mcp/servers/knewstimek/agent-tool/badge" alt="agent-tool MCP server" />
</a>

AI 코딩 에이전트를 위한 MCP(Model Context Protocol) 도구 서버.

## 왜 만들었나?

AI 코딩 에이전트(Claude Code, Cursor, Codex 등)의 내장 도구에는 알려진 한계가 있습니다:

- **탭 들여쓰기 깨짐**: LLM은 공백을 출력하지만, 프로젝트는 탭을 사용. 내장 Edit는 공백을 그대로 써서 들여쓰기 스타일이 망가짐.
- **인코딩 손상**: EUC-KR, Shift-JIS, GB18030 파일을 편집하면 조용히 UTF-8로 변환되어 레거시 프로젝트가 깨짐.
- **도구가 너무 분산됨**: Redis CLI, MySQL/SSH 클라이언트를 따로 찾고 설정하는 과정은 번거롭고 오류가 잦음. agent-tool은 54개 도구를 한 바이너리로 통합하고 compact 프로필에서 필요할 때 활성화함.
- **리버스 엔지니어링 지원 부재**: 내장 도구로는 바이너리 디스어셈블, PE/ELF 헤더 분석, 함수 경계 탐지, 크로스 레퍼런스 검색이 불가능. agent-tool은 정적 바이너리 분석(디스어셈블리, xref, 함수 탐지), DAP 디버거, CheatEngine 스타일 메모리 도구를 포함 -- 에이전트에게 완전한 리버스 엔지니어링 능력을 부여.
- **네트워크 검열**: 일부 국가에서 정부 수준의 웹 필터링으로 `curl`/`wget` 요청이 차단됨. agent-tool은 ECH (Encrypted Client Hello)와 DoH (DNS over HTTPS)를 기본 활성화하여 이런 제한을 우회.

**agent-tool**은 프로젝트 규칙을 보존하면서 모델 컨텍스트를 제한하는 에이전트 지향 도구를 제공합니다.

## 지원 에이전트

Claude Code, Codex CLI, Cursor, Windsurf, Cline, Gemini CLI 및 모든 MCP 호환 에이전트.

## LLM 친화적 기본 동작

기본 `core` 프로필은 54개 전체 스키마 대신 `toolbox`를 포함한 11개만 노출합니다.
실제 MCP 프로토콜 측정에서 직렬화된 도구 목록은 `full` 약 83KB에서 약 17KB로
줄었습니다. 필요할 때 `toolbox`로 그룹/개별 도구만 활성화하거나
`--profile coding|remote|analysis|full`로 시작할 수 있습니다.

대용량 텍스트 결과는 기본 32K자, 절대 상한 128K이며 잘림을 숨기지 않습니다.
페이지 가능 도구는 `next_offset` 또는 `next_cursor`를 반환합니다. 로컬 상대경로는
명시적 workspace, MCP 클라이언트 root, 서버 cwd 순서로 해석됩니다.

## 기능

| 도구 | 설명 | 상태 |
|------|------|------|
| **Edit** | 스마트 들여쓰기 + 인코딩 보존 문자열 치환 (dry_run 지원) | ✅ |
| **Read** | 인코딩 인식 줄번호 읽기. 기본 400줄/32K자, 명시적 truncation과 정확한 `next_offset`, 초장문 행 안전 처리, 선택적 SHA-256, 이미지 ImageContent | ✅ |
| **Write** | 인코딩 인식 파일 생성/덮어쓰기 | ✅ |
| **Grep** | 기본 32K 예산, 파일별 compact 묶음 출력, 상대경로, `.gitignore`/생성 디렉터리 제외, 바이너리 감지, 중복 없는 결정적 `next_cursor` 페이징 | ✅ |
| **Glob** | 정렬·제한된 `**` 검색. 상대경로, 생성 디렉터리 제외, 명시적 `has_more`, 결정적 cursor 페이징 | ✅ |
| **ListDir** | 출력 제한·페이징 디렉토리 목록. max_entries + continuation cursor, 디렉토리/파일 필터, 이름 glob 필터, counts-only, flat/tree 지원 | ✅ |
| **Diff** | 두 파일 비교 (unified diff 출력, 인코딩 인식). 줄바꿈이나 끝 개행만 다른 경우 빈 diff 대신 그 사실을 명시 | ✅ |
| **Patch** | unified diff 패치 적용 (dry_run 지원). 줄마다 자기 줄바꿈을 유지하므로 CRLF/LF 혼합 파일이 재작성되지 않음 | ✅ |
| **Checksum** | 파일 해시 계산 (md5, sha1, sha256) | ✅ |
| **FileInfo** | 파일 메타데이터 (크기, 인코딩, 혼합 줄바꿈별 개수, 들여쓰기, 줄 수) | ✅ |
| **Compress** | zip / tar.gz 압축 | ✅ |
| **Decompress** | zip / tar.gz 해제 (Zip Slip/Bomb 보호) | ✅ |
| **Backup** | 타임스탬프 zip 백업 (제외 패턴 지원). dry_run 미리보기 — 디렉토리별 집계, 패턴별 매칭 수, 큰 파일 목록 | ✅ |
| **ConvertEncoding** | 파일 인코딩 변환 (EUC-KR ↔ UTF-8, BOM 추가/제거 등) | ✅ |
| **Delete** | 안전한 단일 파일 삭제 (디렉토리/심볼릭링크 차단, 시스템 경로 보호, dry_run) | ✅ |
| **Rename** | 원자적 파일/디렉토리 이름 변경 및 이동 (dry_run) | ✅ |
| **SysInfo** | 시스템 정보 — OS, CPU, RAM, 디스크, 업타임, CPU 사용률 측정 | ✅ |
| **FindTools** | 설치된 개발 도구 탐색 — 컴파일러, 런타임, 빌드 시스템 (Go, .NET, Node, Python, Java, Rust, C/C++ 등). PATH, 환경변수, 알려진 경로 탐색 (~/bin, snap, scoop, Homebrew, SDKMAN, nvm, fnm, pyenv) | ✅ |
| **ProcList** | 프로세스 목록 — PID, 이름, 커맨드라인, 메모리. 민감 인자 자동 마스킹. 이름/포트 필터 | ✅ |
| **ProcKill** | PID/포트로 프로세스 종료/일시정지/재개. 트리 킬, 시그널 선택(kill/term/hup/int/stop/cont), 좀비 처리(Linux), dry_run | ✅ |
| **ProcExec** | 명령어를 새 프로세스로 실행. 포그라운드/백그라운드/일시정지 상태 시작 (Windows: CREATE_SUSPENDED, Linux: SIGSTOP). 타임아웃, 환경변수 | ✅ |
| **EnvVar** | 환경변수 조회. 민감 값(비밀번호, 토큰) 자동 마스킹 | ✅ |
| **Firewall** | 방화벽 규칙 조회 — iptables/nftables/firewalld (Linux), netsh (Windows). 읽기 전용 | ✅ |
| **SSH** | 기본 32K head+tail 캡처, 원본 바이트 수, 비정상 종료 오류 의미론, 백그라운드 작업(start/status/tail/cancel). 인증 인식 풀링, 호스트 키 검증, ProxyJump, IPv6 | ✅ |
| **SFTP** | SSH 경유 파일 전송 및 원격 파일시스템 관리. 업로드, 다운로드, ls, stat, mkdir, rm, chmod, rename. 비동기 전송(upload_async/download_async + status/cancel). SSH 세션 풀 재사용. 최대 2GB | ✅ |
| **Bash** | 영속 셸 세션 — 작업 디렉토리, 환경변수 상태 유지. 세션 풀링 (최대 5개, 유휴 타임아웃 30분). Unix: bash/sh, Windows: PowerShell/git-bash/cmd (자동 감지). PowerShell 세션은 UTF-8 인코딩 + PATH 자동 보강 | ✅ |
| **WebFetch** | 기본 32K/최대 128K 웹 콘텐츠 텍스트·마크다운 반환. ECH + DoH, HTML→마크다운, SSRF 차단, 프록시 지원 | ✅ |
| **WebSearch** | Brave Search 또는 Naver API를 통한 웹 검색. API 키 환경변수 필요 (`BRAVE_SEARCH_API_KEY` 또는 `NAVER_CLIENT_ID`/`NAVER_CLIENT_SECRET`). 엔진 자동 선택, Brave 우선 | ✅ |
| **Download** | URL에서 파일 다운로드. ECH + DoH 기본 활성. SSRF 차단. HTTP/SOCKS5 프록시. 원자적 파일 저장. 최대 2GB | ✅ |
| **HTTPReq** | HTTP 요청 실행 (GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS). 커스텀 헤더, 본문, 프록시 지원. API 테스트용. SSRF 차단 | ✅ |
| **JSONQuery** | JSON 파일을 점 표기법으로 쿼리 (예: `dependencies.react`, `items[*].id`). 전체 파일 로드 없이 특정 값만 추출 (토큰 절약) | ✅ |
| **YAMLQuery** | YAML 파일을 점 표기법으로 쿼리 (JSONQuery와 동일 문법) | ✅ |
| **TOMLQuery** | TOML 파일을 점 표기법으로 쿼리 (JSONQuery와 동일 문법). TOML 전용 타입(datetime, int64) 지원 | ✅ |
| **Copy** | 파일/디렉토리 복사. 원자적 쓰기 + 권한 보존. 재귀 디렉토리 복사. Windows 잠긴 파일 폴백 (실행 중인 exe/DLL 이름 변경 후 교체). dry_run 미리보기 | ✅ |
| **Mkdir** | 디렉토리 생성. 8진수 권한 모드 지정 가능 (예: 0755). 기본 재귀 생성 (mkdir -p). dry_run 미리보기 | ✅ |
| **MultiRead** | 최대 50개 파일, 호출 전체 32K 예산, 파일별 기본 200줄, 초장문 행 안전 처리, 파일별/전체 continuation 메타데이터. 해시는 opt-in | ✅ |
| **RegexReplace** | 파일/디렉토리 전체 정규식 찾기-바꾸기. 인코딩과 줄바꿈 보존, 캡처 그룹 ($1, $2) 지원. 바이너리 파일 자동 제외. dry_run 미리보기 | ✅ |
| **TLSCheck** | TLS 인증서 상세 조회 — 주체, 발급자, 만료일, SAN, TLS 버전, 암호화 스위트 | ✅ |
| **DNSLookup** | DNS 레코드 조회 (A/AAAA/MX/CNAME/TXT/NS/SOA). DoH(DNS over HTTPS) 기본 활성 | ✅ |
| **MySQL** | MySQL/MariaDB SQL 쿼리 실행. SELECT 결과의 행·열·셀·전체 출력 제한을 각각 설정 가능하고 DML은 영향 행 수 반환. 페이징은 SQL LIMIT/OFFSET 사용 | ✅ |
| **Redis** | Redis 명령 실행. 타입별 포맷 출력. TLS 지원. 위험 명령(FLUSHALL, SHUTDOWN 등) 차단 | ✅ |
| **PortCheck** | TCP 포트 열림 여부 확인. OPEN/CLOSED 상태 + 응답 시간 반환. 호스트명, IPv4, IPv6 지원 | ✅ |
| **ExternalIP** | 외부(공인) IP 주소 조회. 복수 제공자 자동 fallback (ipify, ifconfig.me, icanhazip) | ✅ |
| **SLOC** | 언어별 소스 코드 라인 수 집계. 70+ 언어 감지, 파일/언어별 분류, 빈 줄 통계, max_depth 제어 | ✅ |
| **Debug** | DAP(Debug Adapter Protocol) 기반 인터랙티브 디버거. 변수값·전체 출력 제한과 variables/completions/modules/loaded_sources 페이징 지원. dlv(Go), debugpy(Python), codelldb(C/C++/Rust) 테스트 완료. 모든 DAP 호환 어댑터 사용 가능. Stdio/TCP 모드. 참고: vsdbg(Microsoft)는 VS Code 라이센스 필수로 단독 사용 불가 — codelldb 또는 netcoredbg를 대안으로 사용 | ✅ |
| **Analyze** | 정적 바이너리 분석 및 리버스 엔지니어링. x86/x64/ARM/ARM64 디스어셈블리, PE/ELF/Mach-O 파싱과 PE import 출력 페이징·상한, xref, 함수/콜그래프, 포인터/RTTI/vtable/구조체 분석, imphash, Rich 헤더, DWARF, 문자열, hexdump, 패턴 검색, 엔트로피, 오버레이, 바이너리 비교. 글로벌 파일 크기 제한 없음 | ✅ |
| **Memtool** | CheatEngine 스타일 프로세스 메모리 도구 — 메모리 값 검색/필터/읽기/쓰기, read_chain(base+offset 포인터 체인을 한 콜에 배치로 해소), 라이브 디스어셈블리(x86/x64/ARM/ARM64), 실행 취소, 구조체 패턴 검색, 포인터 스캔, 메모리 diff. 대용량 스캔을 위한 디스크 기반 스냅샷. 세션 관리 (유휴 타임아웃). Windows (ReadProcessMemory), Linux (/proc/pid/mem). Windows는 elevated 시 SeDebugPrivilege 자동 활성화, opt-in `force_dacl`로 같은 유저의 self-harden DACL 프로세스 우회(원본 DACL 원복) | ✅ |
| **IPC** | AI 에이전트 세션 간 TCP 기반 프로세스 간 통신. 1:1 메시지 전달 (블로킹 수신). 프로토콜: [2바이트 타입][4바이트 길이][페이로드]. 작업: send, receive (타임아웃 블로킹), ping. 다른 PC 간 통신 가능. 최대 1MB 메시지, 300초 타임아웃 | ✅ |
| **Wintool** | Windows GUI 자동화 -- 창/자식 컨트롤 검색/열거, 스크린샷 캡처(ImageContent PNG, PrintWindow), 클립보드 이미지 읽기, 텍스트 읽기/쓰기, 클릭, 타이핑, 원시 메시지 전송, 표시/숨기기/최소화/최대화, 이동/크기 변경, 닫기, 포커스. screenshot/clipboard 기본 ImageContent 반환 (save_path 옵션으로 파일 저장). AI 에이전트가 GUI 앱을 "보고" 조작할 수 있게 함. Windows 전용 | ✅ |
| **CodeGraph** | tree-sitter(WASM) 기반 AST 코드 인덱싱. 11개 operation, 대형 symbols/callees 결과의 offset 페이징과 전체 출력 제한 지원. C/C++, Python, Go, C#, Rust, Java 지원. .gitignore 존중(중첩), venv/vendor/third_party 자동 스킵. LLM 호출 없음, 토큰 비용 0 | ✅ |
| **SetConfig** | 런타임 설정 변경 (인코딩, 파일 크기 제한, symlink, workspace 등) | ✅ |
| **Help** | 에이전트용 사용법 안내 (인코딩, 들여쓰기, 트러블슈팅) | ✅ |

## 핵심 개선사항

### 스마트 들여쓰기
LLM은 보통 공백으로 출력하지만, 많은 프로젝트가 탭을 사용합니다. AgentTool은 파일의 기존 스타일에 맞게 들여쓰기를 자동 변환합니다.

- `.editorconfig`에서 `indent_style`, `indent_size` 읽기
- 설정이 없으면 파일 내용 기반 감지 (앞 100줄 스캔)
- 레거시 파일 보호: 실제 내용이 `.editorconfig`와 다르면 변환하지 않음

### 인코딩 보존
UTF-8로 강제 변환하지 않고, 원본 파일 인코딩을 유지합니다.

- **감지 우선순위**: BOM → `.editorconfig` charset → BOM 없는 UTF-16 → 유효한 UTF-8 → chardet 자동 감지 → 폴백 인코딩
- **지원 인코딩**: UTF-8, UTF-8 BOM, EUC-KR, Shift-JIS, ISO-8859-1, UTF-16 (LE/BE, BOM 유무 무관) 등
- **ASCII 오탐 경고 없음**: 유효한 UTF-8 은 직접 검증하므로 순수 ASCII 파일에 신뢰도 경고가 뜨지 않음
- **줄바꿈**: LF, CRLF, CR, 혼합 파일을 구분. `edit`은 CRLF/LF 어느 쪽이든 여러 줄 `old_string`을 매칭하며(둘이 섞인 파일 포함), `edit`/`regexreplace`로 삽입되는 문자열은 해당 위치 구역의 줄바꿈을 따라가므로 나머지 바이트는 그대로 유지됨

### 토큰을 보호하는 디렉토리 목록
`listdir`는 기본적으로 페이지당 500개까지만 반환하고, 항목이 더 있으면
`next_cursor`를 제공합니다. `directories_only`, `files_only`, `name_pattern`
(예: `A*`) 또는 여러 OR 패턴을 받는 `include`로 결과를 좁힐 수 있습니다.
이름이 필요 없으면 `counts_only=true`로 파일/디렉토리 개수만 반환합니다.

### 유휴 메모리 반환
툴 호출 없이 30분이 지나면 서버가 힙을 OS 에 반환한다. stdio MCP 서버는 "버려진
클라이언트" 와 "조용한 클라이언트" 를 구분할 수 없다 -- 서버를 띄운 프로세스가 살아있는
채로 파이프만 쥐고 있으면 EOF 가 영영 오지 않는다 -- 그래서 추측으로 종료하면 잠시 쉬던
세션을 죽이게 된다. 메모리 반환은 그 거래의 안전한 절반이다: 50MB 파일을 한 번 읽은
인스턴스가 200MB 를 계속 쥐고 있는 대신 기준선인 ~20MB 로 돌아간다. 열려있는 shell/ssh
세션은 그대로 유지되고, 클라이언트가 관찰할 수 있는 동작은 아무것도 바뀌지 않는다.

## 빠른 시작

1. [Releases](https://github.com/knewstimek/agent-tool/releases/latest)에서 OS에 맞는 바이너리 다운로드
2. `agent-tool install` 실행 (또는 `agent-tool install claude` 등 특정 에이전트)
3. IDE / 에이전트 재시작
4. 끝 — 모든 도구가 권한 팝업 없이 바로 사용 가능

또는 AI 에이전트에게 시키세요:
> "https://github.com/knewstimek/agent-tool/releases/latest 에서 agent-tool을 다운받고 `agent-tool install` 실행해줘"

Claude Code, Codex 등 AI 코딩 에이전트가 다운로드 → 설치 → 재시작까지 알아서 처리합니다.

### 권장: 에이전트에게 agent-tool 우선 사용 지시

설치 후 에이전트가 agent-tool을 사용할 수 있게 되지만, 기본 내장 도구(Read, Edit 등)를 계속 쓸 수 있습니다. 에이전트가 agent-tool을 **우선 사용**하게 하려면 아래 지시를 추가하세요.

**코드 탐색 팁**: 대규모 프로젝트에서 AST 기반 코드 탐색을 사용하려면 CLAUDE.md / AGENTS.md에 추가하세요:

```
At the start of a session, run codegraph(op="index", path="<project_root>") to build a code index.
Then use codegraph for structural queries (find, callers, callees, methods, inherits) instead of grep.
```

**Strict** 또는 **Soft** 선택:

| 모드 | 사용 시점 | 지시문 |
|------|----------|--------|
| **Strict** | 비 UTF-8 파일이나 혼합 들여쓰기 프로젝트 | `ALWAYS use agent-tool MCP tools (mcp__agent-tool__*) instead of built-in file tools. agent-tool preserves file encoding and respects .editorconfig indentation settings.` |
| **Soft** | 일반 프로젝트 | `Prefer agent-tool MCP tools (mcp__agent-tool__*) over built-in file tools when available.` |

**어디에 넣을까:**

<details>
<summary><b>Claude Code</b> — CLAUDE.md (프로젝트별) 또는 전역 설정</summary>

**프로젝트별** — 프로젝트의 `CLAUDE.md`에 추가:
```
ALWAYS use agent-tool MCP tools (mcp__agent-tool__*) instead of built-in file tools.
```

**전역** (모든 프로젝트) — `~/.claude/CLAUDE.md`에 추가:
```
ALWAYS use agent-tool MCP tools (mcp__agent-tool__*) instead of built-in file tools.
```

**강제 적용** — `~/.claude/settings.json`으로 내장 도구를 권한 레벨에서 차단:
```json
{
  "permissions": {
    "deny": ["Read", "Edit", "MultiEdit", "Write", "Glob", "Grep"]
  }
}
```
Claude Code의 내장 파일 도구를 아예 사용 불가 상태로 만들어 에이전트가 agent-tool을 쓰도록 강제합니다. 프롬프트 지시에 의존하지 않고 확실히 적용하고 싶을 때 권장.
</details>

<details>
<summary><b>Codex CLI</b> — model_instructions.md (전역)</summary>

1. `~/.codex/config.toml`에 추가 (최상위 레벨, `[mcp_servers.*]` 안이 **아님**):
```toml
model_instructions_file = "~/.codex/model_instructions.md"
```

2. `~/.codex/model_instructions.md` 파일 생성:
```
ALWAYS use agent-tool MCP tools (mcp__agent-tool__*) instead of built-in file tools.
```

3. Codex 재시작.

**프로젝트별** — 프로젝트의 `AGENTS.md`에 추가해도 됩니다.
</details>

<details>
<summary><b>Cursor / Windsurf / Cline</b> — .cursorrules 또는 AGENTS.md</summary>

프로젝트의 `.cursorrules`, `.windsurfrules`, 또는 `AGENTS.md`에 추가:
```
ALWAYS use agent-tool MCP tools (mcp__agent-tool__*) instead of built-in file tools.
```
</details>

## 설치

### 자동 설치 (권장)

```bash
# 감지된 모든 에이전트에 자동 등록 (전체 자동 승인 — 모든 도구)
agent-tool install

# Safe 모드 — 로컬 파일 도구만 자동 승인 (SSH, HTTP, DB, 셸 제외)
agent-tool install --safe-approve

# 자동 승인 없음 — 모든 도구 호출에 수동 승인 필요
agent-tool install --no-auto-approve

# 특정 에이전트에만 등록
agent-tool install claude
agent-tool install claude --safe-approve

# 제거 (agent-tool 항목만 삭제, 다른 설정은 보존)
agent-tool uninstall          # 모든 에이전트에서 제거
agent-tool uninstall claude   # 특정 에이전트에서만 제거
```

**설치 권한 수준:**

| 수준 | 플래그 | 자동 승인 도구 |
|------|--------|----------------|
| Full (기본) | _(없음)_ | 모든 도구 (`mcp__agent-tool__*` 와일드카드) |
| Safe | `--safe-approve` | 29개 로컬 전용 도구 (read, edit, write, grep, glob 등) — SSH, HTTP, DB, bash, 프로세스 제어 제외 |
| None | `--no-auto-approve` | 없음 — 모든 호출에 수동 승인 필요 |

승인 수준과 스키마 프로필은 별개입니다. 전체 네임스페이스를 승인해도 서버는
토큰 효율적인 `core` 프로필로 시작할 수 있습니다.

### 수동 설정

**Claude Code / Cursor / Cline** (`settings.json` 또는 `mcp.json`):
```json
{
  "mcpServers": {
    "agent-tool": {
      "command": "/path/to/agent-tool"
    }
  }
}
```

**Codex CLI** (`~/.codex/config.toml`):
```toml
[mcp_servers.agent-tool]
command = "/path/to/agent-tool"
```

### 옵션

```bash
# 초기 스키마 프로필 선택 (기본: core)
agent-tool --profile coding

# UTF-8이 아닌 프로젝트에서 폴백 인코딩 지정
agent-tool --fallback-encoding EUC-KR
```

프로필: `core`(11개 스키마), `coding`, `remote`, `analysis`, `full`.
실행 중에는 `toolbox`의 `operation=enable`, `groups=["remote"]` 또는 개별
`tools`로 필요한 기능만 추가할 수 있습니다.

### 환경변수

세션마다 CLI 플래그를 반복하지 않으려면 환경변수를 설정하세요:

```bash
# Windows (관리자 권한 불필요)
setx AGENT_TOOL_FALLBACK_ENCODING EUC-KR
setx AGENT_TOOL_PROFILE coding

# Linux / macOS (~/.bashrc 또는 ~/.zshrc에 추가)
export AGENT_TOOL_FALLBACK_ENCODING=EUC-KR
export AGENT_TOOL_PROFILE=coding
```

우선순위: CLI 플래그 > 환경변수 > 기본값 (UTF-8).

### 런타임 설정

에이전트가 `set_config` 도구로 재시작 없이 설정을 변경할 수 있습니다:

| 파라미터 | 설명 | 기본값 |
|----------|------|--------|
| `fallback_encoding` | 자동 감지 실패 시 폴백 인코딩 | `UTF-8` |
| `encoding_warnings` | 인코딩 감지 경고 표시 | `true` |
| `max_file_size_mb` | read/edit/grep 최대 파일 크기 (MB) | `100` |
| `allow_symlinks` | tar 압축 해제 시 symlink 생성 허용 | `false` |
| `workspace` | 명시적 로컬 루트. 미설정 시 첫 MCP 클라이언트 root, 이후 cwd 사용 | _(MCP root/cwd)_ |
| `allow_http_private` | webfetch/download/httpreq의 사설 IP 접근 허용 | `false` |
| `allow_mysql_private` | mysql 도구의 사설 IP 접근 허용 | `true` |
| `allow_redis_private` | redis 도구의 사설 IP 접근 허용 | `true` |
| `allow_ssh_private` | ssh/sftp 도구의 사설 IP 접근 허용 | `true` |
| `enable_doh` | DNS over HTTPS 글로벌 활성화 (webfetch/download/httpreq/dnslookup) | `true` |
| `enable_ech` | Encrypted Client Hello 글로벌 활성화 (webfetch/download/httpreq) | `true` |

## 빌드

```bash
go build -o agent-tool .
```

크로스 컴파일:
```bash
GOOS=linux GOARCH=amd64 go build -o agent-tool .
GOOS=darwin GOARCH=arm64 go build -o agent-tool .
GOOS=windows GOARCH=amd64 go build -o agent-tool.exe .
```

## 트러블슈팅

### 한글/일본어가 깨져 보일 때 (인코딩 문제)

**방법 1**: `.editorconfig`에 `charset` 추가:
```ini
[*]
charset = euc-kr
```

**방법 2**: 환경변수로 영구 설정:
```bash
setx AGENT_TOOL_FALLBACK_ENCODING EUC-KR   # Windows
export AGENT_TOOL_FALLBACK_ENCODING=EUC-KR  # Linux
```

**방법 3**: CLI 플래그 (세션별):
```bash
agent-tool --fallback-encoding EUC-KR
```

### 에이전트용 내장 도움말

agent-tool은 `agent_tool_help` 도구를 제공합니다. 에이전트가 인코딩 경고나 깨진 텍스트를 만나면 자동으로 사용법을 확인할 수 있습니다.

사용 가능 토픽: `overview`, `encoding`, `indentation`, `tools`, `troubleshooting`

## 보안

agent-tool은 강력한 시스템 접근 기능(SSH, MySQL, Redis, 파일 작업, HTTP 요청)을 제공합니다.
AI 코딩 에이전트와 함께 사용할 때 프롬프트 인젝션 위험에 유의하세요:

- **SSRF 보호**: 클라우드 메타데이터 IP (169.254.x.x, fe80::/10)는 설정과 무관하게 항상 차단됩니다. 사설 IP 접근은 프로토콜별로 `set_config`로 설정 가능 (`allow_http_private`, `allow_mysql_private`, `allow_redis_private`, `allow_ssh_private`)
- **DLP (데이터 유출 방지)**: 모든 HTTP 요청 본문에서 민감 데이터 패턴(PEM 개인키, AWS 액세스 키, GitHub/GitLab 토큰, Slack 토큰, .env 파일 덤프)을 스캔하고 **전송 전 차단**합니다
- **프롬프트 인젝션 경고**: 사설 IP 접속 시 마다 보안 경고를 표시하여 웹 콘텐츠에서 주입된 프롬프트 인젝션 공격을 탐지할 수 있도록 합니다 (사용자와 AI 에이전트 모두에게 표시)
- **Zip Slip 보호**: `../` 경로 조작을 통한 Path Traversal 차단 (zip, tar 모두)
- **Zip Bomb 보호**: 단일 파일 1GB, 총 추출 크기 5GB 제한
- **Symlink**: 기본 스킵 (보안). `set_config allow_symlinks=true`로 활성화 (tar만 지원). 활성화해도 outputDir 밖을 가리키는 symlink는 차단
- **파일 크기 제한**: 설정 가능한 최대 파일 크기 (기본 100MB)로 OOM 방지. `set_config max_file_size_mb=N`으로 조절 가능
- **인코딩 안전성**: chardet는 64KB 샘플만 사용하여 메모리 효율적

보안을 위해 AI 에이전트의 도구 호출을 승인 전에 검토하세요. 특히 SSH 명령, 외부 URL로의 HTTP 요청, 데이터베이스 쿼리에 주의가 필요합니다.

## 기술 스택

- **언어**: Go
- **MCP SDK**: [github.com/modelcontextprotocol/go-sdk](https://github.com/modelcontextprotocol/go-sdk)
- **인코딩**: saintfish/chardet + golang.org/x/text
- **배포**: 단일 바이너리 (크로스 컴파일)

## 라이선스

[MIT](LICENSE)
