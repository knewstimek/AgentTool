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
- **도구가 너무 분산됨**: 에이전트에게 Redis CLI, MySQL 클라이언트, SSH 클라이언트 등을 찾고, 설치하고, 설정하게 시키는 과정 자체가 번거롭고 오류가 잦음. agent-tool은 47개 도구를 단일 바이너리로 통합 — 한 번 설치하면 전부 동작.
- **네트워크 검열**: 일부 국가에서 정부 수준의 웹 필터링으로 `curl`/`wget` 요청이 차단됨. agent-tool은 ECH (Encrypted Client Hello)와 DoH (DNS over HTTPS)를 기본 활성화하여 이런 제한을 우회.

**agent-tool**은 프로젝트의 규칙을 존중하는 대체 도구를 제공합니다.

## 지원 에이전트

Claude Code, Codex CLI, Cursor, Windsurf, Cline, Gemini CLI 및 모든 MCP 호환 에이전트.

## 기능

| 도구 | 설명 | 상태 |
|------|------|------|
| **Edit** | 스마트 들여쓰기 + 인코딩 보존 문자열 치환 (dry_run 지원) | ✅ |
| **Read** | 인코딩 인식 파일 읽기 (줄 범위 지정) | ✅ |
| **Write** | 인코딩 인식 파일 생성/덮어쓰기 | ✅ |
| **Grep** | 인코딩 인식 정규식 내용 검색 | ✅ |
| **Glob** | `**` 재귀 지원 파일 패턴 매칭 | ✅ |
| **ListDir** | 디렉토리 목록 (flat 또는 tree) | ✅ |
| **Diff** | 두 파일 비교 (unified diff 출력, 인코딩 인식) | ✅ |
| **Patch** | unified diff 패치 적용 (dry_run 지원) | ✅ |
| **Checksum** | 파일 해시 계산 (md5, sha1, sha256) | ✅ |
| **FileInfo** | 파일 메타데이터 (크기, 인코딩, 줄바꿈, 들여쓰기, 줄 수) | ✅ |
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
| **SSH** | SSH로 원격 서버 명령 실행. 비밀번호/키 인증 (PEM, OpenSSH, PuTTY PPK), 세션 풀링, 호스트 키 검증 (strict/tofu/none), ProxyJump, IPv6 | ✅ |
| **SFTP** | SSH 경유 파일 전송 및 원격 파일시스템 관리. 업로드, 다운로드, ls, stat, mkdir, rm, chmod, rename. 비동기 전송(upload_async/download_async + status/cancel). SSH 세션 풀 재사용. 최대 2GB | ✅ |
| **Bash** | 영속 셸 세션 — 작업 디렉토리, 환경변수 상태 유지. 세션 풀링 (최대 5개, 유휴 타임아웃 30분). Unix: bash/sh, Windows: PowerShell/git-bash/cmd (자동 감지). PowerShell 세션은 UTF-8 인코딩 + PATH 자동 보강 | ✅ |
| **WebFetch** | 웹 콘텐츠를 텍스트/마크다운으로 가져오기. ECH(Encrypted Client Hello) + DoH(DNS over HTTPS) 기본 활성. HTML→마크다운 자동 변환. SSRF 차단. HTTP/SOCKS5 프록시. Chrome User-Agent. **주의:** 페이지 전체 내용을 반환(기본 10만자)하므로 컨텍스트 윈도우 토큰을 많이 소비할 수 있음 — `max_length`로 제한하거나, 단순 검색은 에이전트 내장 웹 도구 사용 권장 | ✅ |
| **WebSearch** | Brave Search 또는 Naver API를 통한 웹 검색. API 키 환경변수 필요 (`BRAVE_SEARCH_API_KEY` 또는 `NAVER_CLIENT_ID`/`NAVER_CLIENT_SECRET`). 엔진 자동 선택, Brave 우선 | ✅ |
| **Download** | URL에서 파일 다운로드. ECH + DoH 기본 활성. SSRF 차단. HTTP/SOCKS5 프록시. 원자적 파일 저장. 최대 2GB | ✅ |
| **HTTPReq** | HTTP 요청 실행 (GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS). 커스텀 헤더, 본문, 프록시 지원. API 테스트용. SSRF 차단 | ✅ |
| **JSONQuery** | JSON 파일을 점 표기법으로 쿼리 (예: `dependencies.react`, `items[*].id`). 전체 파일 로드 없이 특정 값만 추출 (토큰 절약) | ✅ |
| **YAMLQuery** | YAML 파일을 점 표기법으로 쿼리 (JSONQuery와 동일 문법) | ✅ |
| **TOMLQuery** | TOML 파일을 점 표기법으로 쿼리 (JSONQuery와 동일 문법). TOML 전용 타입(datetime, int64) 지원 | ✅ |
| **Copy** | 파일/디렉토리 복사. 원자적 쓰기 + 권한 보존. 재귀 디렉토리 복사. Windows 잠긴 파일 폴백 (실행 중인 exe/DLL 이름 변경 후 교체). dry_run 미리보기 | ✅ |
| **Mkdir** | 디렉토리 생성. 8진수 권한 모드 지정 가능 (예: 0755). 기본 재귀 생성 (mkdir -p). dry_run 미리보기 | ✅ |
| **MultiRead** | 여러 파일을 한 번에 읽기 (API 왕복 절약). 인코딩 인식, offset/limit 지원. 최대 50개 | ✅ |
| **RegexReplace** | 파일/디렉토리 전체 정규식 찾기-바꾸기. 인코딩 보존, 캡처 그룹 ($1, $2) 지원. dry_run 미리보기 | ✅ |
| **TLSCheck** | TLS 인증서 상세 조회 — 주체, 발급자, 만료일, SAN, TLS 버전, 암호화 스위트 | ✅ |
| **DNSLookup** | DNS 레코드 조회 (A/AAAA/MX/CNAME/TXT/NS/SOA). DoH(DNS over HTTPS) 기본 활성 | ✅ |
| **MySQL** | MySQL/MariaDB SQL 쿼리 실행. SELECT 결과 테이블 포맷, DML은 영향 행 수 반환. 최대 1000행 | ✅ |
| **Redis** | Redis 명령 실행. 타입별 포맷 출력. TLS 지원. 위험 명령(FLUSHALL, SHUTDOWN 등) 차단 | ✅ |
| **PortCheck** | TCP 포트 열림 여부 확인. OPEN/CLOSED 상태 + 응답 시간 반환. 호스트명, IPv4, IPv6 지원 | ✅ |
| **ExternalIP** | 외부(공인) IP 주소 조회. 복수 제공자 자동 fallback (ipify, ifconfig.me, icanhazip) | ✅ |
| **SLOC** | 언어별 소스 코드 라인 수 집계. 70+ 언어 감지, 파일/언어별 분류, 빈 줄 통계, max_depth 제어 | ✅ |
| **Debug** | DAP(Debug Adapter Protocol) 기반 인터랙티브 디버거. DAP 전체 커버리지: 브레이크포인트(소스/함수/데이터/명령어/예외), 스텝(정방향/역방향), 변수 조회/수정, 표현식 평가, 디스어셈블리, 메모리 읽기/쓰기, 콜스택, 모듈, goto, 자동완성. dlv(Go), debugpy(Python), codelldb(C/C++/Rust) 테스트 완료. 모든 DAP 호환 어댑터 사용 가능. Stdio/TCP 모드. 참고: vsdbg(Microsoft)는 VS Code 라이센스 필수로 단독 사용 불가 — codelldb 또는 netcoredbg를 대안으로 사용 | ✅ |
| **Analyze** | 정적 바이너리 분석 — x86/x64/ARM/ARM64 디스어셈블리, PE/ELF/Mach-O 파싱(RWX 경고, 리소스, 임포트, 익스포트), imphash, Rich 헤더, DWARF 디버그 정보, 문자열 추출, hexdump, 헥스 패턴 검색, 엔트로피 분석, 오버레이 탐지, 바이너리 비교 | ✅ |
| **Memtool** | CheatEngine 스타일 프로세스 메모리 도구 — 메모리 값 검색/필터/읽기/쓰기, 라이브 디스어셈블리(x86/x64/ARM/ARM64), 실행 취소, 구조체 패턴 검색, 포인터 스캔, 메모리 diff. 대용량 스캔을 위한 디스크 기반 스냅샷. 세션 관리 (유휴 타임아웃). Windows (ReadProcessMemory), Linux (/proc/pid/mem) | ✅ |
| **Wintool** | Windows GUI 자동화 — 창/자식 컨트롤 검색/열거, 스크린샷 캡처(base64 PNG, PrintWindow), 텍스트 읽기/쓰기, 클릭, 타이핑, 원시 메시지 전송, 표시/숨기기/최소화/최대화, 이동/크기 변경, 닫기, 포커스. AI 에이전트가 GUI 앱을 "보고" 조작할 수 있게 함. Windows 전용. 참고: DRM/오버레이 보호가 있는 앱(일부 게임, 스트리밍 앱)은 검은 스크린샷이 반환될 수 있음 — Windows 수준의 캡처 제한이며 도구 한계가 아님 | ✅ |
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

- **감지 우선순위**: `.editorconfig` charset → chardet 자동 감지 → 폴백 인코딩
- **지원 인코딩**: UTF-8, UTF-8 BOM, EUC-KR, Shift-JIS, ISO-8859-1, UTF-16 등
- **줄바꿈**: `\r\n` / `\n` 원본 유지

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
# UTF-8이 아닌 프로젝트에서 폴백 인코딩 지정
agent-tool --fallback-encoding EUC-KR
```

### 환경변수

세션마다 CLI 플래그를 반복하지 않으려면 환경변수를 설정하세요:

```bash
# Windows (관리자 권한 불필요)
setx AGENT_TOOL_FALLBACK_ENCODING EUC-KR

# Linux / macOS (~/.bashrc 또는 ~/.zshrc에 추가)
export AGENT_TOOL_FALLBACK_ENCODING=EUC-KR
```

우선순위: CLI 플래그 > 환경변수 > 기본값 (UTF-8).

### 런타임 설정

에이전트가 `set_config` 도구로 재시작 없이 설정을 변경할 수 있습니다:

| 파라미터 | 설명 | 기본값 |
|----------|------|--------|
| `fallback_encoding` | 자동 감지 실패 시 폴백 인코딩 | `UTF-8` |
| `encoding_warnings` | 인코딩 감지 경고 표시 | `true` |
| `max_file_size_mb` | read/edit/grep 최대 파일 크기 (MB) | `50` |
| `allow_symlinks` | tar 압축 해제 시 symlink 생성 허용 | `false` |
| `workspace` | glob 등에서 경로 미지정 시 사용할 기본 프로젝트 루트 | _(cwd)_ |
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
- **파일 크기 제한**: 설정 가능한 최대 파일 크기 (기본 50MB)로 OOM 방지. `set_config max_file_size_mb=N`으로 조절 가능
- **인코딩 안전성**: chardet는 64KB 샘플만 사용하여 메모리 효율적

보안을 위해 AI 에이전트의 도구 호출을 승인 전에 검토하세요. 특히 SSH 명령, 외부 URL로의 HTTP 요청, 데이터베이스 쿼리에 주의가 필요합니다.

## 기술 스택

- **언어**: Go
- **MCP SDK**: [github.com/modelcontextprotocol/go-sdk](https://github.com/modelcontextprotocol/go-sdk)
- **인코딩**: saintfish/chardet + golang.org/x/text
- **배포**: 단일 바이너리 (크로스 컴파일)

## 라이선스

[MIT](LICENSE)
