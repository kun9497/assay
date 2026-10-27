# 2026-10-27 소스 리뷰 수정

[English](2026-10-27-source-review-fixes.md) · 한국어

2026-10-27 소스 리뷰와 그 재리뷰(둘 다 `0d09e22` 기준)는 P2 결함 세 건을 보고했습니다. 각 결함은
독립적으로 검증했고, 원인에서 고쳤으며, 실제 호출 경로를 거치고 수정 전에는 실패하던 회귀 테스트로
고정했고, 결정으로 기록했습니다. 로드맵의 D150, D151, D152 입니다. 작업을 시작했을 때 `main` 은
`0d09e22` 였으므로 이미 고쳐진 것은 없었습니다. 첫 리뷰의 Oracle train 경계 후보는 바뀌지 않았고
여전히 확인된 결함이 아닙니다. 수정 전 릴리스 빌드에서는 찾지 못했습니다.

| # | 결함 | 결정 | 수정이 필요로 하는 것 |
|---|---|---|---|
| 1 | SPDX source 관계가 source EVR 을 버림 | D152 (D143 개정) | 새 바이너리 (스캔 시점) |
| 2 | `install.sh` 가 base64 에 위치 인자 파일을 넘김 (macOS) | D151 | 다음 릴리스의 `install.sh` |
| 3 | 읽지 못한 서명 페이로드가 무효한 서명으로 분류됨 | D150 | `db update` 는 새 바이너리; `dbstatus` 는 다음 실행 (워크플로는 `go run` 을 씁니다) |

세 건 모두 데이터베이스 재빌드가 필요하지 않습니다.

## 1. SPDX source 관계가 이름은 유지하고 EVR 은 버렸습니다 (D152)

**검증.** 재리뷰의 실제 권고 프로브를 `0d09e22` 에서 다시 돌렸습니다. `redhat.convert` 로 CVE-2023-23920
에 대한 Red Hat 의 CSAF 문서를 변환한 뒤, nodejs 로 빌드된 최소 SPDX npm 을 매칭합니다. 결과는
`nodejs` 를 통해 매칭된 발견 하나, skip 없음이었습니다. source 에는 이름이 있고 버전이 없었습니다.
실제 문서를 다시 내려받았고, 리뷰어의 사본과 바이트 단위로 같습니다(sha256 `9f6b64f001ca1d045b6c…`).
첫 리뷰의 합성 Fedora 프로브도 다시 돌렸습니다: httpd `2.4.62-1.fc40` 에서 나온 mod_ssl
`1:2.4.62-1.fc40` 을 httpd fix `2.4.63-1.fc40` 과 비교하면 exit 0, 발견 없음, 불완전 없음이었습니다.

**원인.** D143 은 바이너리에 source rpm 의 이름만 주었습니다. 매처는 source 이름으로 한 조회를
`Source.Version` 이 있으면 그것과(D41), 없으면 바이너리 자신의 버전과 비교합니다. 그래서 npm `8.19.3`
이 nodejs fix `16.19.1` 과 비교되었고, mod_ssl 의 epoch 1 은 epoch 없는 httpd fix 보다 높게
정렬되었습니다. D143 은 빈 버전을 이미지 경로로 정당화했는데, 이미지 경로는 바이너리의 EVR 을
`Source.Version` 으로 기록합니다. 이는 감사 발견 A4 이며 그 자체로 결함입니다.

**수정.** `sourceRPMOf` 는 source 자신의 purl 에서 source 의 EVR 을 유지합니다(`pkgmeta.EVROf`:
`@version` 에, `epoch` 한정자가 있고 0 이 아니면 그것을 앞에 붙임. 바이너리 purl 이 이미 쓰던 규칙).
파일: `internal/cataloger/spdx/spdx.go`, `internal/pkgmeta/distropurl.go`. 매처는 바뀌지 않았습니다.
관계 자격, `upstream` 우선순위(이름만), 바이너리 이름, source 이름, provides 조회는 바뀌지 않았습니다.

**전 → 후.**
- **실제 CVE-2023-23920, 고쳐진 npm:** nodejs 를 통한 Medium 발견 하나 → 없음.
- **같은 문서, fix 이전에 빌드된 npm:** 발견됨 → 여전히 발견됨.
- **합성 mod_ssl, httpd 에서:** exit 0 이고 놓침 → exit 1, httpd 를 통해 발견.

**네임스페이스 확인.** source EVR 은 source 이름의 레코드가 source 의 버전을 기술할 때만 맞습니다.
Fedora Bodhi 는 source NVR 을 기록합니다. Red Hat 의 fixed 목록은 `.src` 옆에 arch 바이너리를 이름으로
나열합니다. 실제 문서에서 같은 플랫폼의 `.src` 와 같은 이름의 바이너리 쌍은 모두 같은 EVR 을 가집니다
(D80 이 따로 범위를 정하는 모듈 스트림 빌드를 따로 두면 7 중 7).

**범위 밖: A4.** 이미지 경로는 여전히 `rpmdb/header.go` 에서 바이너리의 EVR 을 `Source.Version` 으로
기록합니다. SOURCERPM 은 epoch 없는 파일 이름이며, source epoch 를 바이너리의 것에서 추론해서는
안 됩니다. A4 에는 자체 결정과 실제 이미지에 대한 측정이 필요합니다. 이 수정은 SPDX 문서가 명시적으로
밝힌 것만 사용합니다.

**테스트** (표시한 곳은 수정 전에 실패했습니다):
- `internal/scancmd/spdx_source_evr_test.go`: `TestRun_SPDXSourceRelationshipComparesTheSourceEVR`
  (실패: 고쳐진 npm 이 보고됨)과 `TestRun_SPDXSourceRelationshipDoesNotBorrowTheBinaryEpoch`
  (실패: mod_ssl 을 놓침).
- `internal/provider/redhat/spdx_source_evr_test.go`: `TestRealCSAF_SPDXSubpackageIsJudgedOnItsSourcesEVR`,
  Red Hat 의 실제 문서(`testdata/cve-2023-23920.json.gz`)로.
- `internal/cataloger/spdx/generates_test.go`: 빈 버전을 요구하던 D143 의
  `TestParse_A3_ASubpackageWithItsOwnReleaseKeepsItsSource` 는 이제 `1:16.19.1-1.el9_2` 를 요구합니다.
  새로 추가: `TestParse_SourceEVRComesFromTheSourcePURLOnly` 와 `TestParse_ASourceWithNoVersionGivesNoEVR`.
  `upstream` 우선순위 테스트도 이제 버전이 없음을 요구합니다.
- 변이 테스트: 변이 6개, 모두 잡힘.
- 리뷰어의 프로브는 결함에서 통과하도록 쓰였습니다. 수정 뒤에는 옛 동작을 단언하는 부분에서 실패합니다:
  실제 CSAF 프로브는 발견 0 과 `Source.Version=1:16.19.1-1.el9_2` 를 봅니다.

## 2. install.sh 가 macOS 에서 서명을 디코드하지 못했습니다 (D151)

**검증.** Apple 의 base64(text_cmds `bintrans.c`)는 입력을 stdin 이나 `-i` 로만 읽습니다. 위치 인자
파일은 거기서 사용법 오류이므로, `base64 -d file` 은 openssl 이 돌기 전에 실패했고 설치 스크립트는
서명이 검증되지 않는다고 말했습니다. Apple 의 인자 파서를 쓰는 하네스 경우(C8)가 고치지 않은 설치
스크립트에서 실패했습니다.

**수정.** `install.sh` 는 `base64 -d <file` 을 씁니다. 하네스(`scripts/install_test.sh`)는 더 이상
GNU 전용 플래그(`base64 -w0`, `sha256sum --text`)를 쓰지 않습니다. 환경 변수를 설정하는 각 경우를
서브셸에서 돌리고, 실패를 파일에 기록하며, C8 이 추가되었습니다. CI 는 이것을 macOS-latest 에서
돌립니다. 파일: `install.sh`, `scripts/install_test.sh`, `.github/workflows/ci.yml`.

**네이티브 macOS.** 첫 macOS 실행은 수정된 설치 스크립트로 진짜 릴리스를 설치했습니다(C1). 그러고서
하네스에서 여덟 개 경우가 실패했습니다: macOS 의 `/bin/sh`(bash 3.2, POSIX 모드)는 셸 함수 앞에 쓴
`VAR=x` 를 호출 뒤에도 유지하므로 한 경우의 변수가 다음 경우로 샜습니다. POSIX 는 이를 규정하지
않고, dash 는 유지하지 않습니다. 서브셸을 쓰면 macOS-latest 에서 하네스 전체가 통과합니다: 진짜 설치,
변조된 아카이브, 낡은, 삭제된, 외부의 서명, `PATH` 에 검증기 없음, 키 교체, C8. 서명 검사는 약해지지
않았습니다.

## 3. 읽지 못한 서명 페이로드가 무효한 서명으로 분류되었습니다 (D150)

**검증.** 재리뷰의 독립 호출자 테스트를 `0d09e22` 에서 다시 돌렸습니다. manifest 403 대조는 통과했고,
blob 403, 404, 503 하위 테스트는 실패했습니다: `signed:false`, 새 관찰 시각, 빈 `publishedError`.

**원인.** `Verify` 는 `verifyLayer` 의 모든 오류를, blob 가져오기 실패까지 포함해,
`ErrNoKeyVerifies` 로 바꿨습니다.

**수정.** 레이어가 무효인 것은 ggcr 가 받은 바이트가 틀렸다고 보고하거나(다이제스트, 크기, Content-Length)
읽을 수 있는 바이트에 대한 검사가 실패할 때뿐입니다. 그 밖의 모든 페이로드 읽기 오류는 레이어를 unread 로
표시합니다: 재시도 뒤의 레지스트리 오류(본문이 무엇이든 가장 먼저 판정), 네트워크 오류, HTTP/1 에서 중간에
끊기거나 HTTP/2 에서 리셋된 스트림, 취소된 컨텍스트, 또는 예상하지 못한 종류. 첫 버전은 대신 전송 오류를
나열했고, 브랜치 리뷰가 HTTP/2 스트림 리셋이 여전히 무효로 분류됨을 찾았습니다. 다른 레이어는 여전히
시도하며 하나라도 검증되면 받아들입니다. 검증된 것이 없고 unread 가 하나 있으면 `Verify` 는 `ErrSignatureUnreadable` 을
반환하며, `db update` 와 `dbstatus` 는 이미 이를 전송 실패로 다룹니다. 자기 다이제스트와 바이트가 맞지
않는 blob 은 여전히 무효입니다. 파일: `internal/dbcmd/trust/verify.go`.

**전 → 후.**
- **서명 blob 403/404/503 에서의 dbstatus:** `signed:false`, 새 `observedAt`, 빈 `publishedError` →
  이전의 서명된 설명이 유지되고 오류가 기록됨.
- **blob 403 에서의 `db update`:** "does not verify under any key" → "fetch signature: …403…".
  pull 은 `--allow-unsigned` 의 유무와 관계없이 여전히 거부됩니다.

**테스트:**
- `cmd/dbstatus/sigblob_test.go`: blob 403, 404, 503 (모두 수정 전에 실패).
- `internal/dbcmd/pull_sigblob_test.go`: blob 403, `--allow-unsigned` 있을 때와 없을 때 (수정 전에
  실패).
- `internal/dbcmd/trust/verify_unreadable_test.go`, 다루는 것:
  - 각 상태는 unreadable 입니다;
  - 읽지 못한 레이어가 진짜 레이어 옆에 있으면 순서와 관계없이 여전히 받아들입니다;
  - 무효 레이어가 읽지 못한 레이어 옆에 있으면 unreadable 입니다;
  - 페이로드와 같은 길이로 다이제스트가 맞지 않는 blob 과, 길이가 틀린 blob 은 무효입니다;
  - 끊긴 스트림, 가져오는 도중 끝난 컨텍스트, ggcr 문구를 인용한 레지스트리 오류는 unreadable 입니다.
- `internal/dbcmd/trust/readfailure_h2_test.go`: 페이로드 도중의 HTTP/2 스트림 리셋은 unread 입니다
  (수정 첫 버전에서 실패).
- 리뷰어의 프로브는 이제 4 중 4 를 통과합니다 (이전에는 4 중 1).
- 변이 테스트, 두 차례:
  - 첫 버전에 대해 9개: 7개가 잡혔고, 2개는 서로 등가였으며 해당 절은 이후 제거됨;
  - 뒤집은 규칙에 대해 4개, 모두 잡힘. 그중 하나는 다이제스트 경우에 페이로드와 같은 길이를 준 뒤에야
    잡힘.

## 검증

Windows 11, Go 1.26, `GOFLAGS=-mod=readonly`, 브랜치 head 에서 실행했습니다:

- `go test ./...`: 통과. `go vet ./...` 와 `gofmt -l`: 깨끗함.
- `scripts/install_test.ps1`: Windows PowerShell 5.1 과 7 모두에서 모든 경우 통과. install.ps1 은
  바뀌지 않았습니다.
- Git Bash 에서 `scripts/install_test.sh`: 모든 경우 통과. C5 는 설계대로 Windows 에서 건너뜁니다.
  CI 에서는 PR #199 run 40451869250, macOS-latest: C5 와 C8 을 포함해 모든 경우가 통과합니다. Linux
  job 도 통과합니다.
- 같은 overlay 에 대한 리뷰어들의 프로브:
  - trust 프로브는 4 중 4 를 통과합니다 (`0d09e22` 에서는 4 중 1);
  - 옛 동작을 단언하는 SPDX 프로브 셋은 이제 그 동작에서 실패합니다.
- 변이 테스트 (메인 루프, 커밋된 기준선, 한 번에 변이 하나):
  - trust: 첫 버전에 9개(7개 잡힘, 서로 등가 2개는 이후 제거), 최종 규칙에 4개(모두 잡힘);
  - SPDX: 6 중 6;
  - 셸 하네스: C8 이 고치지 않은 설치 스크립트에서 실패.
- **검증 중 발견:** Windows CI 구간이 2026-10-27 에 `internal/dbcmd` 에서 두 번(한 번은 `main` 자체에서)
  시간 초과(10분)되었습니다. 원인은 등급 7,249개를 트랜잭션 7,249개로 쓰며 각각 fsync 하던 테스트
  헬퍼였습니다. 이제 한 트랜잭션으로 씁니다(로컬에서 116초에서 16초). 테스트 전용입니다.

**실행하지 않은 것.**
- 로컬에서 `-race` 없음: 여기에는 C 툴체인이 없고, CI 가 돌립니다.
- 실제 워크플로, 데이터베이스 재빌드, 게시 없음.
- CI 밖의 직접 Mac 사용 없음.
- 고치지 않은 설치 스크립트를 실제 Mac 에서 돌리지 않았습니다. 결함은 GNU 플랫폼에서 C8 의 Apple
  의미론 shim 으로 보이고, 고친 설치 스크립트는 CI 가 실제 Mac 에서 보입니다.
- 태그가 붙은 라이브 피드 테스트는 다시 돌리지 않았습니다(코드 변경 없음).

## 릴리스와 재빌드

- **D152 (SPDX)** 는 스캔 시점 코드입니다: 다음 바이너리 릴리스와 함께 사용자에게 닿습니다.
  데이터베이스 재빌드 없음.
- **D150 (trust)** 는 바이너리(`db update`)와, 워크플로가 머지된 커밋에서 `go run` 으로 돌리는
  `cmd/dbstatus` 에 있습니다. 따라서 `status.json` 은 머지 뒤 첫 워크플로 실행부터 바로잡히고,
  `db update` 는 다음 릴리스와 함께 바로잡힙니다. 데이터베이스 재빌드 없음.
- **D151 (install.sh)**: README 는 `install.sh` 를 릴리스 커밋으로 고정합니다. 고친 스크립트는
  `scripts/prepare-release.sh` 와 README 고정 뒤의 다음 릴리스와 함께 macOS 사용자에게 닿습니다. 그
  전에는 Mac 사용자가 머지 커밋에서 `install.sh` 를 받거나 `go install` / 릴리스 페이지를 쓸 수
  있습니다.

## 부작용과 남은 한계

- D152 는 SPDX 입력의 판정만 바꾸며, 버전이 source 의 것과 다른 관계로 연결된 rpm 바이너리에 한합니다.
  네임스페이스를 가로지른 비교에서 나온 발견은 사라집니다(npm 같은 오탐). 그것이 가리던 발견은
  나타납니다(mod_ssl 같은). 이미지 경로의 A4 는 바뀌지 않았습니다.
- D150 은 설치 결정을 바꾸지 않습니다: 읽지 못한 서명은 전에도 거부되었고 지금도 그렇습니다. 오류의
  종류와 문구만 바뀌며, `dbstatus` 는 거짓 장애를 게시하지 않게 됩니다.
- D151 은 서명이 openssl 에 닿는 방식만 바꿉니다. Linux 동작은 같습니다(C1–C8 이 GNU base64 와 dash
  에서 통과).
- Oracle train 경계 후보는 리뷰가 든 이유로 조치하지 않았습니다.

## 다시 검증하기

머지 커밋의 클론에서(PowerShell 또는 Git Bash):

```sh
GOFLAGS=-mod=readonly go test ./internal/cataloger/spdx ./internal/pkgmeta ./internal/scancmd ./internal/provider/redhat -run 'SPDXSource|SourceEVR|RealCSAF|A3_|NoVersionGivesNoEVR' -count=1 -v
GOFLAGS=-mod=readonly go test ./internal/dbcmd/trust ./internal/dbcmd ./cmd/dbstatus -run 'Unreadable|CutShort|ContextEnded|DoesNotMatchItsDigest|UnreadableSignatureBlob' -count=1 -v
sh scripts/install_test.sh          # C8 = Apple base64 semantics; C5 needs Linux/macOS
GOFLAGS=-mod=readonly go test ./... && go vet ./...
```

리뷰어들의 원래 프로브는 그대로입니다(`$R` = 리뷰 폴더):

```sh
go test -overlay "$R/source-rereview-2026-10-27/trust/overlay.json" ./cmd/dbstatus -run TestIndependentReview -count=1 -v   # now 4/4 PASS
go test -overlay "$R/source-rereview-2026-10-27/spdx/overlay.json" ./internal/provider/redhat -run TestReReview20261027 -count=1 -v   # now FAILS: 0 findings
go test -overlay "$R/source-review-2026-10-27/matcher/overlay.json" ./internal/scancmd -run TestReview20261027 -count=1 -v   # now FAILS: bad behaviour gone
```

각 결함이 되돌아오는 것을 보려면 파일 하나를 `0d09e22` 로 되돌리고 그 테스트를 다시 돌립니다:
`git checkout 0d09e22 -- internal/cataloger/spdx/spdx.go internal/pkgmeta/distropurl.go`
(SPDX 테스트가 실패), `-- internal/dbcmd/trust/verify.go` (trust 테스트가 실패), 또는
`-- install.sh` (C8 이 실패). 실제 권고의 증거:
`internal/provider/redhat/testdata/cve-2023-23920.json.gz` 는 Red Hat 의 문서입니다
(압축을 풀면 sha256 `9f6b64f001ca1d045b6c…`). 결정: 로드맵 D150, D151, D152.
