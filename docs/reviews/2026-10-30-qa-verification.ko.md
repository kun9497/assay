# QA 2026-10-30 — 검증과 수정

[English](2026-10-30-qa-verification.md) (원문) · 한국어

이 문서는 2026-10-30 QA 보고서에 답합니다. 보고서는 QA 작업 공간의
`qa-2026-10-30/qa-report.md` 와 `qa-report.ko.md` 에 있고, 증거는 같은 폴더에 있습니다. 여기 적은
모든 주장은 2026-10-30 에 아래에 적은 커밋을 대상으로 실행한 명령에서 나왔으며, 9절이 그 명령을
나열합니다. 릴리스한 것도, 데이터베이스를 게시한 것도, 배포한 것도 없습니다.

## 1. 기준선과 변경 범위

**QA 의 기준선.** QA 는 D157 브랜치(PR #209)인 `2d0ae5d` 에서 실행했고, 같은 브랜치의 `f824794` 는
따로 리뷰했습니다. 두 커밋 모두 `main` 에 없습니다. PR #209 는 2026-10-30 에 열린 채 병합되지 않았습니다.

**이 검증의 기준선.** 깨끗하게 체크아웃한 `650bedb`(Merge #207)의 `origin/main`. QA 결함은 하나씩
고치기 전에 `650bedb` 에서 재현했습니다(3절). D157 은 Ubuntu provider 와 `db push` 를 건드립니다.
아래 결함 중 어느 것도 둘과 관계가 없으며, 수정 브랜치는 #209 와 Go 파일을 하나도 공유하지 않습니다.

**수정.** 브랜치 `fix/qa-1030`, 로컬 전용: push 하지 않았고 PR 도 없습니다. `650bedb` 위 커밋:

| 커밋 | 항목 |
|---|---|
| `e61e46c` | ① 긴 줄 |
| `3679652`, `a5b2ad5`, `70601ba` | ③ range 순서 (수정, 이어서 뮤테이션 라운드 테스트 둘) |
| `2f1166b`, `63c1b86` | ④ HTTP/2 재시도 (수정, 이어서 뮤테이션 라운드 테스트 하나) |
| `0bb17e4` | ⑤ VEX 바깥 index |
| `a778d79` | ② toolchain 하한과 릴리스 바이너리 스캔 |
| `f954506` | 문서: 로드맵 EN; CHANGELOG 와 DESIGN, EN 과 KO |
| (후속) | 문서: 로드맵 KO, 그리고 이 문서와 그 한국어 사본 |

수정 브랜치에는 ⑥ 과 ⑦ 이 들어 있지 않습니다. 이미 열려 있던 PR 에 있습니다:
- ⑥ 은 #208 (브랜치 `fix/a10-layer-shadowing`);
- ⑦ 은 #212 (브랜치 `feat/d158-sarif-catalog-skips`).

## 2. 판정

| # | QA 항목 | QA 심각도 | `650bedb` 에서의 판정 | 처분 |
|---|---|---|---|---|
| ① | 긴 줄이 Gemfile.lock, Cargo.lock, uv.lock 을 잘라 냄 | P2 | **재현됨.** 읽기 코드 두 곳(requirements.txt, pom.properties)에도 같은 결함이 있었음 | 수정, `fix/qa-1030` |
| ② | 릴리스가 Go 1.26.9 로 빌드됨; GO-2026-6809 는 1.26.10 에서 수정됨 | P2 | 동등한 재빌드에서 **재현됨**, 게시된 자산에서는 아님(내려받지 못함) | 강제, `fix/qa-1030` |
| ③ | opens 가 먼저인 OSV range 가 단일 버전 구간을 넓힘 | P2 | **재현됨** | 수정, `fix/qa-1030` |
| ④ | HTTP/2 blob 본문이 reset 되어도 재시도하지 않음 | P2 | **재현됨** | 수정, `fix/qa-1030` |
| ⑤ | 중첩 index 의 바깥 index 를 지목한 VEX 가 적용되지 않음 | P2 | `oci-dir:` 와 registry 경로 모두에서 **재현됨** | 수정, `fix/qa-1030` |
| ⑥ | 정규 파일이 아닌 상위 레이어 항목이 하위 패키지 DB 를 가리지 않음 | P3 | **재현됨** | #208 에서 수정 (열려 있음) |
| ⑦ | 카탈로그 수준 skip 이 SARIF 결과를 만들지 않음 | P3 | **재현됨** | #212 에서 수정 (열려 있음) |
| — | Alpaquita 주간 초과 (69 > 66) | — | **회귀 아님:** advisory 증가 | 상한은 이미 `1c25df5` (#189)가 재조정함; 여기서는 바꾸지 않음 |

## 3. 항목별

각 수정은 테스트를 먼저 썼습니다. 테스트는 수정 전 코드에서 빨강, 수정에서 초록으로 돌렸습니다.
그런 다음 새 호출 지점과 분기를 하나씩 커밋된 기준선에 대해 변이시키고 스위트를 다시 돌렸습니다.

### ① 64 KiB 를 넘는 줄이 lockfile 의 인벤토리를 잘라 냅니다

- **조건.** Gemfile.lock, Cargo.lock, uv.lock, requirements.txt 의 dir: 스캔, 또는 jar 의
  `pom.properties` 에 64 KiB 를 넘는 줄이 하나라도 있는 경우. 긴 주석이나 공백 줄이면 충분합니다.
- **영향.** 그 줄 뒤의 패키지가 모두 사라졌고, 읽기 코드는 성공을 보고했습니다. 스캔은 나머지를 파일
  전체로 판정했습니다: exit 0, `components` 는 그 줄 앞의 패키지만 셌고, 불완전 표시는 없었습니다. 줄
  아래의 critical 패키지는 조용한 거짓 음성이었습니다. `pom.properties` 는 그 줄 뒤의 키를 잃어서 jar 가
  "버전 없음, 평가 안 됨"으로 집계되었습니다. 그쪽은 눈에 보였지만 여전히 틀렸습니다.
- **원인.** 각 읽기 코드가 `bufio.Scanner` 로 줄을 나누고 `Err()` 를 읽지 않았습니다. 스캐너는 64 KiB
  를 넘는 첫 토큰에서 `ErrTooLong` 으로 멈추고, 루프는 그냥 끝납니다. QA 는 gemlock 과 tomlblock 을
  지목했습니다. `internal/cataloger` 의 모든 `bufio.NewScanner` 를 훑었더니 `Err()` 확인이 없는 곳이
  둘 더 있었습니다: requirements 와 jar. requirements 자신의 주석은 그 한계가 "fail loudly" 하게 만든다고
  주장했습니다.
- **수정.** 각 읽기 코드는 이미 가진 바이트를 직접 나눕니다(`bytes.Lines` / `strings.Lines`). 그래서
  너무 길어 읽지 못하는 줄이 없습니다. 한계를 올리지 않았고 무시한 오류도 없습니다. `ScanLines` 의 CR
  처리는 유지합니다. 파일은 이미 `source.MaxFileBytes` (D112)로 제한됩니다.
  - `internal/cataloger/gemlock/gemlock.go:44`
  - `internal/cataloger/tomlblock/tomlblock.go:55`
  - `internal/cataloger/requirements/requirements.go:146`
  - `internal/cataloger/jar/jar.go:312`
- **테스트.**
  - `internal/scancmd/longline_test.go` `TestRun_QA1030_ALongLineDoesNotHideTheLockfileBelowIt`
    는 dir: 대상에 대해 네 가지 매니페스트 유형 × {128 B, 70 KiB} 로 `Run` 을 호출하며
    `--fail-on critical` 과 `--fail-on-incomplete` 를 줍니다. exit 1, 줄 아래의 패키지가 발견에 포함됨,
    `components == 2` 를 단언합니다.
  - `internal/cataloger/jar/jar_test.go` `TestParse_PropertiesAfterALongLineAreRead`.
- **검증 실행.**
  - **빨강.** 각 읽기 코드를 `650bedb` 로 되돌리거나(requirements) 64 KiB 를 넘는 줄에서 멈추도록
    변이시키면(gemlock, tomlblock) 해당하는 70 KiB 하위 테스트가 실패합니다. gemlock 은 하위 테스트 1개,
    tomlblock 은 2개(Cargo.lock, uv.lock), requirements 는 1개가 실패합니다. jar 의 옛 `parseProperties`
    는 자기 테스트에서 실패합니다.
  - **초록.** 수정에서 모두 통과합니다.
  - **QA 자신의 프로브** (`matcher/runtime_qa_test.go`, 수정 없음)를 수정 위에서: 크기가 큰 행은 모두
    이제 `components 2`, `findings 1`, exit 1 을 보고하며 짧은 줄 대조군과 같습니다. `650bedb` 에서는
    큰 행이 exit 0 을 보고했습니다.
- **QA 와의 차이.** QA 의 프로브는 exit 2("읽지 않음으로 보고")를 단언합니다. 노트에는 "완전히 읽는
  구현이 취약한 패키지를 탐지하고 exit 1 로 끝나는 것도 정당할 수 있다"는 말도 있습니다. 택한 길이
  그것입니다. 읽을 수 있는 줄은 거부할 입력이 아닙니다. 그래서 그 여섯 단언은 수정에서 여전히 실패하며
  이는 의도한 것이고, 출력은 대조군과 일치합니다.

### ② 릴리스 toolchain: GO-2026-6809

- **분리해 둔 증거.** 서로 다른 질문에 답하는 출처 넷:
  1. **QA 의 소스 스캔** (`govulncheck-cli.txt`)은 로컬 Go **1.26.7** 로 실행했습니다: 발견 10건.
     아홉 건은 **1.26.9** 에서 수정되었으므로 1.26.9 로 빌드한 바이너리에는 해당하지 않습니다.
     GO-2026-6809 (crypto/x509, "distrust compromised intermediate certificates", **1.26.10** 에서
     수정)만 해당합니다.
  2. **릴리스 빌드 로그** (`release-build-log.txt:204`, 2026-10-27, v0.12.0)에는
     `go version go1.26.9 linux/amd64` 가 보입니다. setup-go 의 `go-version: "1.26"` 이 러너에
     캐시된 패치 릴리스를 가져왔습니다.
  3. **게시된 산출물** (v0.12.0 자산)은 **스캔하지 않았습니다.** 이 기기에서 릴리스 자산 다운로드는
     TLS 핸드셰이크 타임아웃으로 실패하며, QA 도 그랬습니다.
  4. 대신 **동등한 재빌드**를 스캔했습니다. 이 트리를 GoReleaser 가 빌드하는 방식
     (`CGO_ENABLED=0 -trimpath -ldflags "-s -w"`)으로 linux/amd64 용으로 빌드했습니다:
     - `GOTOOLCHAIN=go1.26.9` 로 빌드: govulncheck v1.9.0 `-mode=binary` 가 **GO-2026-6809**
       (crypto/x509@go1.26.9 에서 발견, go1.26.10 에서 수정)를 보고하고, 종료 코드는 0 이 아닙니다;
     - `GOTOOLCHAIN=go1.26.10` 로 빌드: "No vulnerabilities found", exit 0.
- **오늘 필요한 패치 수준.** 공식 데이터베이스(`vuln.go.dev`, 2026-10-30 에 읽음)에는 2026-09-01 이후
  수정된 stdlib 및 toolchain advisory 가 21건 있습니다. 1.26 라인에서 가장 높은 fix 는
  **go1.26.10** 이며 GO-2026-6809 하나에서 나옵니다. 나머지는 1.26.9 에서 수정되었습니다. go1.26.10 은
  릴리스되었습니다(`go.dev/dl`).
- **수정** (`a778d79`):
  - **하한.** `go.mod` `toolchain go1.26.10`.
  - **`scripts/check-go-toolchain.sh`.** `go env GOVERSION` 을 go.mod 의 toolchain 줄과 비교해 더
    낮으면 실패합니다. `release.yml` 의 GoReleaser 앞과 `ci.yml` 의 build job 에서 돕니다. 빌드가 실제로
    쓴 toolchain 을 검사합니다: `GOTOOLCHAIN=auto` 이면 go 명령이 스스로 하한까지 올리고, 더 낮은 Go 로
    `GOTOOLCHAIN=local` 에 고정된 러너는 실패합니다.
  - **`scripts/release-vulncheck.sh`.** govulncheck v1.9.0 (2026-10-11 릴리스)을 바이너리 모드로
    돌립니다. `.goreleaser.yaml` 이 각 빌드의 post hook 으로 돌리므로, 아카이브·서명·게시 전에
    strip 되고 교차 컴파일된 바로 그 바이너리가 스캔됩니다. 발견이 있으면 릴리스가 실패합니다.
  - **`internal/ciguard/toolchain_test.go`.** 연결을 고정합니다: go.mod 에 toolchain 줄이 있고,
    release.yml 이 GoReleaser 앞에서 검사를 돌리고, ci.yml 도 돌리고, 모든 GoReleaser 빌드에 hook 이
    있습니다. 버전 숫자는 일부러 고정하지 않습니다. 그 숫자는 go.mod 의 것입니다.
- **검증 실행.**
  - **검사.** `sh scripts/check-go-toolchain.sh` 는 "Go 1.26.10 meets go1.26.10" 을 출력합니다
    (exit 0). `GOTOOLCHAIN=local` (Go 1.26.7)이면 "error: Go 1.26.7 is older than go1.26.10…"
    을 출력합니다 (exit 1).
  - **스캔.** 다시 빌드한 두 바이너리에 `scripts/release-vulncheck.sh` 를 돌리면 1.26.9 는 exit 1,
    1.26.10 은 exit 0 입니다.
  - **뮤테이션.** ciguard 테스트는 네 가지 각각에서 실패합니다: 릴리스 단계 제거, CI 단계 제거, hook
    제거, go.mod 의 toolchain 줄 제거.
- **하지 않은 것.**
  - 이 수정은 v0.12.0 을 다시 빌드하거나 다시 릴리스하지 않습니다.
  - GoReleaser 는 로컬에서 실행하지 않았습니다. hook 문법은 GoReleaser v2 의 `builds[].hooks.post`
    입니다. **병합 뒤 첫 태그 릴리스를 지켜봐야 하며**, 태그 전에
    `goreleaser release --snapshot --clean` 도 돌려야 합니다(8절).

### ③ opens 가 먼저인 range 가 단일 버전 구간을 넓힙니다 (D154)

- **조건.** 이벤트 목록이 두 open 을 두 close 앞에 두는 OSV range:
  - `[introduced 1, introduced 3, last_affected 1, last_affected 3]`;
  - `[introduced 1, introduced 2, fixed 1, fixed 3]`.
- **영향.** 거짓 양성. 첫 range 에서는 2.0.0 이 영향받는 것으로 판정되었고, 다른 순서에서는 4.0.0 도
  그랬습니다. 두 번째에서는 1.5.0 이 영향받는 것으로 판정되었습니다. `--fail-on` 에서 exit 1 이고
  불완전 검사는 없습니다. 게시된 데이터베이스에서는 발생 사례가 없습니다(아래).
- **원인.** `splitDegenerate` 가 파일 순서에서 다음 `introduced` 앞에 있는 open 뒤의 첫 close 하고만
  open 을 짝지었습니다. 어느 구간도 떼어 내지 않았습니다. 그러면 D154 의 동률 규칙(close 가 open 앞)이
  range 를 `[1, 3]` 으로 읽었습니다. OSV 는 이벤트를 정렬하라고 권하지만 요구하지는 않습니다. 이는
  2026-10-30 에 다시 읽었습니다
  (https://ossf.github.io/osv-schema/#affectedranges-events-fields). 참조 알고리즘은 정렬하며
  동률은 규정하지 않습니다.
- **수정.** `internal/version/rangeeval.go`:
  - `pairByVersion` (`:359`)은 파일 순서 패스 뒤에 돌며 남은 이벤트를 버전 순서로 걸어갑니다. 각 버전 X
    바로 아래에 열린 구간이 있는지 추적합니다. 없으면 X 에서의 각 open 이 X 에서의 close 하나를 가져가고
    그 쌍은 따로 판정됩니다. 있으면 close 하나는 그 구간을 끝내려고 걸음 안에 남고(만나는 구간에 대한
    D154 의 규칙, 바뀌지 않음), 그 너머의 close 만 짝을 이룹니다.
  - `eventLess` (`:467`)는 `sortEvents` 의 비교자를 떼어 낸 것이어서 둘이 같이 씁니다.
- **테스트.**
  - `internal/version/rangeeval_ties_test.go` `TestInRange_QA1030_AWindowsCloseNeedNotFollowItsOpen`
    은 네 이벤트짜리 range 여섯 가지의 모든 순서(각 24가지)를 돌립니다:
    - 단일 버전 구간 둘;
    - 빈 구간과 실제 구간;
    - 빈 구간 둘;
    - 닫힌 구간 위의 빈 구간;
    - 그리고 대조군 둘: 만나는 구간, 그리고 더 넓은 구간이 닫히는 곳의 단일 버전 구간.

    QA 모양에는 증거를, 모든 경우에는 판정을 단언합니다.
  - `internal/scancmd/rangeorder_test.go` `TestRun_QA1030_EventOrderDoesNotWidenSingleVersionWindows`
    는 npm 2.0.0, 3.0.0, 4.0.0 의 CycloneDX SBOM 에 대해 이벤트를 opens 먼저와 정렬된 순서로 두고
    `Run` 을 호출합니다. exit 1 과 3.0.0 하나에만 발견이 있음을 단언합니다.
- **검증 실행.**
  - **`650bedb` 에서 빨강.** 단언 실패 134건, 2.0.0 과 4.0.0 이 영향받는 것으로 판정된 경우 포함.
  - **수정에서 초록.** 기존의 A7/D154 테스트는 모두 수정 없이 통과합니다.
  - **뮤테이션.** 일곱 개, 모두 잡힘:
    - 호출 제거;
    - 예약 제거;
    - 상태를 설정하지 않음, 또는 항상 설정;
    - 하나짜리 그룹;
    - 정렬하지 않음;
    - 아무 close 나 가져감.

    1 라운드의 "항상 설정" 생존자는 range 두 개를 더해 닫았습니다(`a5b2ad5`, `70601ba`). 호출을
    제거하면 `Run` 테스트도 실패합니다.
  - 2026-10-27 의 **게시된 데이터베이스**를 A7 하네스로: 동률 range 536개, 각 range 자신의 경계에서
    프로브 2,892개. 출력은 전후가 **바이트 단위로 같습니다**: 프로덕션 데이터에서는 판정도 증거도
    바뀌지 않았습니다.
  - **QA 자신의 프로브** (`matcher/prior-range_test.go`, 수정 없음): `650bedb` 에서 하위 테스트 7개 중
    3개가 실패하고, 수정에서는 7개 모두 통과합니다.
- **남은 한계.** 판정이 아니라 증거입니다. 만나는 두 구간 안에 파일이 `[X,X)` 를 별도 구간으로 나열하면
  D154 의 파일 순서 패스가 그것을 떼어 냅니다. 그러면 X 아래 버전의 증거는 `[open, X)` 가 아니라
  `[open, final close)` 를 가리킵니다. D154 부터 그랬고, 판정은 어떤 순서에서도 같습니다.

### ④ 다운로드 도중의 HTTP/2 stream reset 은 재시도되지 않습니다 (D140)

- **조건.** 데이터베이스 레이어 일부를 보낸 뒤 stream 을 reset 하는 HTTP/2 registry 에 대한 `db update`
  (`Pull`) 또는 `db build --seed` (`PullSeed`).
- **영향.** 가용성. pull 이 첫 GET 에서 `stream error: stream ID N; INTERNAL_ERROR; received from peer`
  로 실패했고, 수동으로 다시 돌리면 성공했습니다. 무결성은 온전했습니다: 이전 데이터베이스는 바이트
  단위로 그대로였고 임시 파일은 지워졌습니다. QA 도 같은 것을 관찰했습니다.
- **원인.** D140 의 `interruptedTransfer` 는 `io.ErrUnexpectedEOF`, `ECONNRESET`, `EPIPE`,
  `net.ErrClosed`, 실패한 소켓 읽기, 네트워크 타임아웃을 인식했습니다. HTTP/2 의 stream 오류는
  net/http 의 비공개 `http2StreamError` 이고, 위 어느 것에도 맞지 않습니다.
- **수정.** `internal/dbcmd/pull.go`:
  - **태깅 transport.** `bodyTransport` (`:477`)가 세 곳의 `remote.Image` 호출 모두에서 registry
    transport 를 감쌉니다. `taggedBody.Read` (`:489`)는 응답 본문의 EOF 가 아닌 읽기 오류를 모두
    `bodyReadError` 로 감싸고, `interruptedTransfer` (`:451`)가 그것을 재시도합니다.
  - **태깅이 아티팩트 자체의 결함을 걸러 내는 이유.** 오류 문자열을 맞추는 것이 아니라 바이트가 어디서
    오는지로 작동합니다. go-containerregistry 의 digest 와 크기 검사는 그 reader 위에서 읽고, gzip 의
    헤더와 CRC 도 그 위에서 읽으므로, 손상된 레이어에는 태그가 붙지 않습니다.
  - **컨텍스트.** `unpackWithRetry` (`:427`)는 이제 컨텍스트를 받고 그것이 끝나면 재시도하지 않습니다.
    `--timeout` 마감은 전에는 네트워크 타임아웃으로 읽혀 성공할 수 없는 컨텍스트로 재시도되었습니다.
  - **바뀌지 않은 것.** 상한은 세 번 시도 그대로입니다. 서명 검증(D137)은 unpack 앞에서 돌며
    건드리지 않았습니다. 임시 파일은 지워지고 이전 데이터베이스가 유지됩니다.
- **테스트.** `internal/dbcmd/pull_http2_test.go`, TLS HTTP/2 `httptest` registry 위에서. 테스트는
  레이어의 모든 GET 이 HTTP/2 임을 단언합니다.
  - `TestPull_QA1030_AnHTTP2StreamResetIsRetried`: Pull 과 PullSeed, reset 한 번; exit 0, GET 두 번,
    "retrying (2/3)", 쓸 수 있는 데이터베이스.
  - `TestPull_QA1030_GivesUpAfterThreeResetStreams`: exit 2, GET 정확히 세 번, 이전 데이터베이스가
    바이트 단위로 같음, `.tmp` 없음.
  - `TestPull_QA1030_PermanentFailuresAreNotRetried`: 손상된 레이어, 취소된 pull, 2초 마감을 넘긴 pull.
    각각 GET 정확히 한 번, "retrying" 없음, 이전 데이터베이스가 바이트 단위로 같음, `.tmp` 없음.
- **검증 실행.**
  - **`650bedb` 에서 빨강.** reset 테스트는 실패하고 대조군은 통과합니다.
  - **수정에서 초록.** D140 테스트(`TestPull_RetriesADownloadCutMidStream` 등)는 여전히 통과합니다.
  - **뮤테이션.** 여섯 개, 모두 잡힘:
    - Pull 에서, 또는 PullSeed 에서 transport 제거;
    - 컨텍스트 guard 제거 (마감 대조군을 추가하기 전까지 생존했음);
    - 태그를 적용하지 않음;
    - 태그를 무시함;
    - 본문을 감싸지 않음.
  - **QA 자신의 프로브** (`db/http2_retry_test.go`, 수정 없음): `650bedb` 에서 실패하고 수정에서
    통과합니다(update 와 seed).

### ⑤ 중첩 index 의 바깥 index 를 지목한 VEX (D121)

- **조건.** 바깥 index → 안쪽 index → manifest 로 닿는 이미지, 그리고 product 가 바깥 index digest 를
  지목하는 VEX 문장.
- **영향.** 문장이 건너뛰어졌고 발견이 남았습니다: 생산자가 영향 없음이라고 했는데 exit 1. 바깥 digest
  는 digest 로 하는 registry 참조가 가리키는 것이고 `docker buildx imagetools` 가 출력하는 것입니다.
- **원인.** `collectCandidates` (`internal/source/image.go`)가 각 단계에서 부모를 교체했으므로 후보는
  바로 위 index 만 기억했습니다. `scancmd.vexTarget` 은 manifest 와 그 index 만 맞췄습니다.
- **수정.**
  - **체인.** 각 후보는 `outer []v1.Hash` 를 가집니다. 요청한 index 에서 시작한 경로 위에서 부모 위의
    모든 index 를 가장 바깥부터 담습니다(`image.go:460`). 슬라이스는 자식마다 복사하므로 형제가 backing
    array 를 공유하지 않습니다(`:516`).
  - **보고.** `PlatformChoice.OuterIndexDigests` (`platform.go:70`)가 그것을 담고, `catalogImage` 가
    `vexTarget` 에 넘깁니다(`scancmd.go:745`).
  - **JSON `image` 레코드는 바뀌지 않습니다** (스키마 bump 없음). 체인은 VEX 범위에만 쓰입니다.
  - **체인 밖.** 형제 index, 다른 플랫폼의 manifest, `oci-dir:` 레이아웃 자신의 `index.json` 은 경로
    위에 없습니다.
- **테스트.** `internal/scancmd/vexnested_test.go` `TestRun_QA1030_VEXNamingAnOuterIndexAppliesToTheImageItLists`.
  픽스처는 호스트 플랫폼 안쪽 index 를 담은 바깥 index 와, riscv64 이미지를 가진 형제 index 입니다.
  세 형태로 돌립니다:
  - 플랫폼이 없는 descriptor 의 `oci-dir:` (config-sniff 경로);
  - 바깥 index 의 digest 로 하는 registry;
  - 태그로 하는 registry (descriptor-platform 경로).

  바깥 index, 안쪽 index, manifest 를 지목하는 문장은 적용되어야 합니다(exit 0, 억제 하나). 형제 index,
  다른 플랫폼 manifest, 무관한 digest 를 지목하는 문장은 적용되면 안 됩니다(exit 1, 발견 하나).
- **검증 실행.**
  - **`650bedb` 에서 빨강.** "outer" 하위 테스트 셋만 실패하고 대조군은 모두 통과합니다.
  - **수정에서 초록.** 기존의 VEX, 플랫폼, index 테스트가 통과합니다.
  - **뮤테이션.** 일곱 개, 모두 잡힘:
    - `vexTarget` 에서, 또는 `catalogImage` 에서 바깥 digest 를 버림;
    - 부모를 체인에 더하지 않음;
    - config-sniff 지점에서, 또는 descriptor 지점에서 체인을 비움;
    - `PlatformChoice` 를 설정하지 않음;
    - 형제 사이에 체인을 공유함.
  - **QA 자신의 프로브** (`input/nested_index_vex_test.go`, 수정 없음): 바깥 index 와 registry 경우는
    `650bedb` 에서 실패하고 수정에서 통과하며, 대조군도 포함됩니다.

### ⑥ 정규 파일이 아닌 상위 레이어 항목이 하위 패키지 DB 를 가리지 않습니다 (감사 A10)

- **상태.** PR #208 에서 수정, `fix/qa-1030` 에는 없습니다. 원인과 수정은 #208 의 설명과 로드맵
  항목에 있습니다.
- **검증 실행.** QA 자신의 프로브, 수정 없음 (`image/runtime_qa_test.go`
  `TestQA1030UpperNonregularHidesPackageDB` 와 `TestQA1030RegularAndWhiteoutControls`):
  - **`650bedb` 에서.** 정규 파일이 아닌 네 하위 테스트가 모두 실패합니다: opaque 표지가 있는 디렉터리,
    FIFO, 문자 장치, 블록 장치가 각각 "want exit2, got 0" 을 냅니다. 대조군은 통과합니다.
  - **#208 의 head** (`origin/fix/a10-layer-shadowing`)에서. 대조군을 포함해 모두 통과합니다.

### ⑦ 카탈로그 수준 skip 이 SARIF 결과를 만들지 않습니다 (감사 A16, D158)

- **상태.** PR #212 에서 수정, `fix/qa-1030` 에는 없습니다.
- **검증 실행.** QA 자신의 프로브, 수정 없음 (`TestQA1030CatalogIncompleteSARIF`):
  - **`650bedb` 에서.** `sarif` 하위 테스트가 실패하고 table 과 JSON 은 통과합니다.
  - **#212 의 head 에서.** 셋 모두 통과합니다.
- **종료 코드는 바뀌지 않습니다** (D36/D21). 새 결과는 `assay/not-evaluated` 이며 수준은 `warning` 또는
  `note` 이고, CVE 규칙이 아닙니다.

### Alpaquita 주간: 상한 66 에 69

- **실행.** 2026-10-25/26 의 주간(run 40243397863)이
  `alpaquita 69 / grype 56 / agree 47 / assay-only 22 / grype-only 9 / BREACH` 를 `maxFindings 66`
  에 대해 보고했습니다.
- **이 리뷰 이전.** 커밋 `1c25df5` (PR #189, 2026-10-26)가 이미 상한을 138 로 올렸습니다. 그 근거:
  agree 는 47 로 그대로, assay-only 는 3 → 22, 새 항목은 모두 BellSoft 레코드. 이 리뷰는 어떤 floor 도
  ceiling 도 **바꾸지 않았습니다**.
- **2026-10-27 게시 데이터베이스에 대한 독립 확인.** 레코드가 존재하며 직전 주간(2026-10-19) 이후에
  수정되었습니다:

  | 레코드 | 수정일 | `Alpaquita:stream` 의 range | 패키지 |
  |---|---|---|---|
  | BELL-CVE-2026-88831, 88833 과 형제들 | 2026-10-22 | busybox `[1.36.1-r1, 1.38.0-r6)` | busybox |
  | BELL-CVE-2026-88829 | 2026-10-24 | busybox, introduced 1.36.1-r1, fix 없음 | busybox |
  | BELL-CVE-2026-108119 | 2026-10-22 | busybox `[1.36.1-r1, 1.38.0-r6)` | busybox |
  | BELL-CVE-2026-114406 | 2026-10-23 | `[20220614-r3, 20261020-r0)` | ca-certificates |

  이미지의 busybox 1.38.0-r2 는 모든 busybox range 안에 있습니다. 새 튜플은 BellSoft 자신의 데이터로
  보면 참 양성이며, grype 와 일치하는 집합은 47 로 유지되었습니다. **판정: advisory 증가이며 회귀가
  아닙니다.**
- **`1c25df5` 메시지에 대한 정정 하나.** 그 메시지는 busybox CVE 를 "unfixed" 라고 부릅니다. `stream`
  키에서는 대부분이 1.38.0-r6 의 fix 를 가지고 있고, 88829 만 없습니다.
- **여전히 제한됨.** fix 를 가진 assay-only 튜플은 여전히 `maxAssayOnlyFixed: 41` (D146) 아래에 있으므로,
  `maxFindings` 를 두 배로 해도 거짓 양성의 급증은 여전히 제한됩니다.

## 4. 제품 점검

| 점검 | `650bedb` + 수정에서의 상태 | 증거 |
|---|---|---|
| exit 0 은 "안전"이 아님 | exit 0 은 평가된 것 가운데 `--fail-on` 이상의 발견이 없다는 뜻입니다. 완전하다는 뜻이 아닙니다. 불완전은 `--fail-on-incomplete[=target]` 으로만 게이트됩니다(exit 2, D21/D36). 그 플래그가 없으면 불완전한 스캔도 exit 0 일 수 있습니다. table, JSON, SARIF 가 각각 집계를 담습니다. | D11/D21/D36; `scancmd.go` 의 `verdict()`; SARIF 는 ⑦ |
| 이미지 안에서는 OS 패키지와 Bitnami 만 | 이미지 안의 애플리케이션 패키지는 읽지 않습니다(D70). D141 부터 모든 이미지 스캔이 stderr 와 SARIF (`assay/inventory-scope`)에서 이를 밝히고, JSON 에는 `inventoryScope.applicationPackages: not-read` 가 있습니다. | `TestRun_D141_*` |
| EOL 대 지원 대 알 수 없음 | EOL 은 EOLFrom 다음 날입니다(A9). 답이 없는 조회에서 `--fail-on-eol` 은 경고하고 실패시키지 않습니다. 확정된 답이 필요한 서비스는 "알 수 없음"을 자기만의 정책 결과로 다뤄야 합니다. | `TestRun_EOLUnknownWith*WarnsButDoesNotTrip` |
| 동결된 데이터, builtAt 과 dataAsOf | `DataAsOf` (D12)는 upstream 의 최신성입니다. `BuiltAt` 이 7일을 넘으면 스캔이 경고하고(D139), 스캔이 쓰는 키마다 나이를 판단하며, 동결된 키는 동결된 날부터의 나이입니다(D113). 동결된 키는 table, JSON, SARIF 에 표시됩니다(D110/D111). | `TestRun_D113_*`, `TestRun_D110_*`, `staledb_test.go` |
| SLE→Leap fix 출처 유지 | 미러된 advisory 는 JSON 의 `crossMappedFrom` 과 `--explain` 에서 밝혀집니다(D108/D128). A13 (#207)은 병합된 발견이 표시된 레코드를 따르게 했습니다. | `TestJSON_DisclosesCrossMappedFrom`, `TestExplain_DisclosesCrossMappedFrom` |
| 빈 또는 부분 인벤토리가 깨끗해 보임 | **일부 열려 있음.** 빈 CycloneDX `components[]` 는 불완전 플래그 둘을 모두 줘도 exit 0 입니다. table 은 문서에 컴포넌트가 없었다고 말하고 JSON 은 0 을 셉니다. 이는 deferred-decisions 에 문서화되어 있습니다. 부분 입력, 즉 긴 줄 경우는 ① 로 수정되었습니다. 서비스는 자기만의 최소 인벤토리 정책을 강제해야 합니다. | QA `empty-sbom.*`; `docs/deferred-decisions.md` |

## 5. 해결되지 않은 것과 그 이유

1. **⑥ 과 ⑦ 은 `main` 에 없습니다.** #208 과 #212 가 병합되어야 하며, 둘 다 2026-10-30 에 CI 가
   초록이었습니다. 오늘 `main` 에서 자른 릴리스에는 둘 다 없습니다.
2. **게시된 v0.12.0 바이너리는 스캔하지 않았습니다.** 다운로드가 타임아웃되었습니다. 스캔은 동등한
   재빌드에 대한 것이었습니다(②). 게시된 v0.12.0 은 빌드 로그상 GO-2026-6809 를 안고 있으며, 새
   릴리스만이 그것을 고칩니다.
3. **GoReleaser hook 은 돌려 보지 않았습니다.** 실제 GoReleaser 실행에서 아직 실행된 적이 없습니다(②).
4. **빈 SBOM 은 exit 0 입니다.** 문서화된 제품 정책이며 여기서 바꾸지 않았습니다. 서비스 수준의 최소
   인벤토리 규칙이 필요합니다.
5. 파일이 만나는 구간 사이에 `[X,X)` 를 나열하면 **증거는 여전히 파일 순서를 따릅니다**(③, D154 동작,
   판정에는 영향 없음).
6. **서비스 운영 계층은 저장소에 없습니다.** 이들은 검증되지 않은 릴리스 조건이며, 여기서 구축하지
   않았습니다(7절).
7. **이 기기의 한계.**
   - `-race` 는 돌리지 않았습니다: cgo 툴체인이 없습니다. CI 가 `go test -race ./...` 를 돌립니다.
   - `upstreamvectors` 태그 테스트(네트워크 oracle, 실제 Red Hat 및 SUSE 피드)는 CI 에서만 돕니다.
   - Windows 보안 소프트웨어가 새로 링크한 테스트 바이너리를 간헐적으로 막았습니다(링크 시점의 "Access
     is denied"). 그런 실행은 모두 빌드될 때까지 다시 시도했고, 위의 어떤 결과도 빌드되지 않은 실행에서
     나온 것이 아닙니다. 이는 환경 문제이며 결함이 아닙니다.
8. **부하 테스트, 전체 CVE 판정, 실제 registry 또는 고객 이미지 스캔은 없습니다.** 어느 것도 돌리지
   않았고, 돌렸다고 주장하지도 않습니다.

## 6. 준비 상태

| 용도 | 준비 상태 | 조건 |
|---|---|---|
| **내부 PoC** | `fix/qa-1030`, #208, #212 가 병합되고 CI 가 초록이면 **준비됨** | OS 패키지와 Bitnami 인벤토리에 돌립니다. exit 0 은 "평가된 것 가운데 발견 없음"으로 제시합니다. `--fail-on-incomplete=target` 을 씁니다. |
| **제한된 고객 파일럿** | **조건부 준비됨** | 위의 모든 것에 더해: 새 하한과 바이너리 스캔을 거쳐 go1.26.10 이상으로 빌드한 새 릴리스와, 다시 검증한 그 아카이브(`gh attestation verify`, cosign checksum). 파일럿 대상은 고객 문자열 그대로가 아니라 wrapper 가 CLI 에 넘깁니다. 범위는 "이미지 안에서는 OS 패키지와 Bitnami; 애플리케이션 패키지는 lockfile 과 SBOM 에서만"으로 밝힙니다. 빈 SBOM 을 위한 최소 인벤토리 규칙. 파일럿마다 격리된 자격 증명 환경(D118). |
| **완전한 외부 서비스** | **준비 안 됨** | 7절의 배포 계층이 이 저장소에 없고 검증되지 않았습니다. 이미지 안 애플리케이션 인벤토리(D70)는 구축되지 않았습니다. promote-after-sign 이나 보존된 known-good 데이터베이스(D137 의 가변 태그)에는 운영 SLO 가 없습니다. |

## 7. 검증되지 않은 릴리스 조건: 서비스 운영 계층

저장소는 이것들을 배포에 맡깁니다(`docs/deferred-decisions.md`, "Safe handling of externally supplied
targets"). 여기에 있는 것은 없고 검증된 것도 없습니다:

- **네트워크.** egress 정책, 그리고 registry 호스트와 DNS 허용 목록. 호스트 허용 목록은 없고, 사설
  대역 DNS 응답도 가져오며, go-containerregistry 의 SSRF 검사는 IP 리터럴로의 리디렉션만 다룹니다.
- **입력 종류.** 고객이 지목할 수 있는 것을 제한하는 wrapper: 로컬 경로, `docker-archive:`,
  `oci-dir:` 금지. 걸 곳은 `source.Classify` 입니다.
- **격리.** 스캔마다 프로세스 또는 컨테이너 샌드박스, CPU·메모리·디스크 할당량, 동시성 상한. D112 는
  파일 복사(파일당 512 MiB, 스캔당 2 GiB)를 제한하고 `--timeout` 은 벽시계 시간을 제한하지만, 둘 다
  강한 샌드박스는 아닙니다. 원치 않는 큰 tar 항목 하나가 취소를 지연시킬 수 있습니다.
- **자격 증명.** 고객별, 작업별 `DOCKER_CONFIG`, `REGISTRY_AUTH_FILE`, `ASSAY_REGISTRY_AUTH_*`. 그것이
  없으면 스캔은 호스트 사용자의 로그인을 씁니다(D118).
- **데이터베이스 가용성.** promote-after-sign, 또는 보존된 known-good 아티팩트. `db push` 뒤 서명이
  실패해도 클라이언트가 서명되지 않은 태그를 거부한 채 남지 않게 하기 위함입니다(D137).
- **모니터링.** D157 의 Ubuntu fix-state 개수는 아티팩트 주석에는 있지만 `db status` 나 table 에는
  없습니다. 이는 QA 가 지적한 관측성 공백이며 판정 결함이 아닙니다.

## 8. 다음 릴리스 전에 반드시

1. `fix/qa-1030`, #208, #212 를 병합합니다(그리고 계획대로 #209, #210, #211). `main` 의 CI 가 `-race`
   와 `upstreamvectors` 단계까지 초록인지 확인합니다.
2. go1.26.10 이상으로 `goreleaser release --snapshot --clean` 을 한 번 돌립니다. `release-vulncheck`
   hook 이 바이너리 여섯 개 모두에서 돌고 통과했는지 확인합니다.
3. 그 뒤에야 태그합니다. 태그 실행에서 "Hold the toolchain to go.mod's floor" 가 `go1.26.10` 이상을
   출력했는지, 모든 hook 이 통과했는지 확인합니다.
4. 태그하기 전에 `vuln.go.dev` 를 다시 읽어 go.mod 의 toolchain 줄보다 새로운 stdlib fix 가 있으면
   줄을 올립니다. hook 이 어차피 릴리스를 멈추겠지만, 먼저 올리면 실패한 태그를 피합니다.
5. #209 가 병합된 뒤 첫 nightly 에서 D157 의 Ubuntu floor 를 지켜봅니다. #210 이 병합된 뒤에는 그
   grype 설치 단계의 첫 실행을 지켜봅니다.

## 9. QA 보고서와의 차이

| 주제 | QA | 이 검증 | 이유 |
|---|---|---|---|
| 기준선 | `2d0ae5d` (D157 브랜치) | `650bedb` (`main`) | `2d0ae5d` 는 `main` 에 없습니다. 모든 결함을 `main` 에서 다시 재현했습니다. |
| ① 범위 | gemlock, tomlblock | 더해서 requirements.txt 와 pom.properties | catalogers 의 모든 `bufio.NewScanner` 를 훑었더니 `Err()` 가 없는 읽기 코드가 둘 더 나왔음 |
| ① 기대 결과 | exit 2 단언 (노트에서는 exit 1 도 수용) | 발견과 함께 exit 1 | 줄을 완전히 읽으므로 읽지 않은 것이 없음 |
| ② 발견 | Go 1.26.7 의 govulncheck 에서 10건 | 1.26.9 릴리스에 해당하는 것은 1건 (GO-2026-6809) | 아홉 건은 1.26.9 에서 수정됨. 로컬 toolchain 은 릴리스 toolchain 이 아님. |
| ② 산출물 | — | 동등한 재빌드를 스캔함; 게시된 자산은 아님 | 이 기기에서 다운로드가 타임아웃됨 |
| ③ | P2 거짓 양성 | 확인됨; 2026-10-27 게시 DB 에서는 발생 사례 없음 | A7 하네스 출력이 전후로 같았음 |
| Alpaquita | 분류할 초과 | 증가; `1c25df5` 가 이미 재조정함 | 10-22..10-24 에 수정된 BellSoft 레코드가 이미지의 버전을 덮음 |

## 10. 다시 확인하는 법

저장소에서 `fix/qa-1030` 위에서. `go` 는 `GOFLAGS=` 를 비워 두고 돌립니다. 이 기기의 기본값
`-mod=mod` 가 `go.sum` 을 다시 쓰기 때문입니다.

```
go vet ./...                                   # clean
gofmt -l .                                     # empty
go test -count=1 ./...                         # 56 packages ok, 2026-10-30
go test ./internal/version -run 'QA1030|A7'
go test ./internal/dbcmd   -run 'QA1030|Retr|Broken|Interrupt'
go test ./internal/scancmd -run 'QA1030'
go test ./internal/ciguard
sh scripts/check-go-toolchain.sh               # "Go 1.26.10 meets go1.26.10"
GOTOOLCHAIN=local sh scripts/check-go-toolchain.sh   # fails on an older local Go
```

QA 자신의 프로브를 수정 없이 다시 돌리려면 `go test -overlay` 로 QA 테스트 파일을 패키지마다 하나씩
추가합니다:

| QA 파일 | 패키지 |
|---|---|
| `qa-2026-10-30/matcher/runtime_qa_test.go` | `internal/scancmd` |
| `qa-2026-10-30/matcher/prior-range_test.go` | `internal/scancmd` |
| `committed-review-2026-10-27/db/http2_retry_test.go` | `internal/dbcmd` |
| `committed-review-2026-10-27/input/nested_index_vex_test.go` | `internal/scancmd` |
| `qa-2026-10-30/image/runtime_qa_test.go` | `internal/scancmd`, #208 과 #212 위에서 |
