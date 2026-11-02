# 변경 이력

이 프로젝트의 주목할 만한 변경 사항은 모두 이 문서에 기록합니다. 형식은
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/)를 따르고, 프로젝트는
[Semantic Versioning](https://semver.org/)을 사용합니다. 항목에 따로 적혀 있지 않은 한 JSON 보고서의
`schemaVersion`은 바뀌지 않았습니다. 데이터베이스 저장소 스키마는 v0.1.0 이후 계속 9입니다.

## [Unreleased]

### Added
- `--config none` 은 ignore 파일을 전혀 쓰지 않고 스캔합니다. 작업 디렉터리에서 `.assay.yaml` 을 찾지
  않고 아무것도 waive 하지 않으며, 보고서의 provenance 에는 `ignoreFile.path: "none"` 이 기록됩니다.
  발견(discovery)은 스캔을 실행한 디렉터리를 읽으므로, 직접 작성하지 않은 checkout 을 스캔하면 그
  checkout 이 들고 있는 waiver 목록 아래서 실행됐고, 유일한 탈출구는 `ignore: []` 라고 적힌 파일이었습니다.
  (QA 2026-11-02 P3 #23)

### Changed
- 빈 `--config` 값(`--config=`, `--config ""`)은 parse 단계에서 `none` 을 안내하는 메시지와 함께 거부됩니다.
  전에는 조용히 "발견" 을 뜻했습니다. 그 자리에 비어 있는 변수를 넘기던 잡은 이제 작업 디렉터리의 `.assay.yaml`
  아래서 스캔하는 대신 exit 2 로 끝납니다. (QA 2026-11-02 P3 #23)

### Fixed
- `--fail-on-incomplete` / `--fail-on-incomplete=target` 판정은 exit 2 와 함께 stderr 에 개수와 발동한
  플래그 형태를 담은 `error:` 줄을 출력합니다 --
  `error: N package(s) not evaluated and M check(s) incomplete (--fail-on-incomplete)` 또는
  `error: N package(s), check(s) or manifest(s) of the target itself could not be evaluated
  (--fail-on-incomplete=target)`. 그런 줄이 없는 유일한 exit 2 였고, 비공개 reason 으로 쓰이던 provenance
  sidecar 의 `run.error` 는 `=target` 이 발동했을 때도 `--fail-on-incomplete` 라고 적었습니다. 이제
  sidecar 는 다른 모든 exit 2 처럼 출력된 줄을 기록합니다. stdout 과 exit 코드는 그대로입니다.
  (QA 2026-11-02 P3 #7)
- 모든 finding 이 waive 되고 동시에 무언가 평가되지 않은 스캔의 표 headline 이 "No vulnerabilities found
  in N package(s), but ... NOT a clean result" 라고 적혔고, 그 아래 Suppressed 블록은 finding 을 나열했습니다.
  incomplete 문장들은 이제 "No unwaived vulnerabilities found in N package(s) (M suppressed), but ..." 로
  시작하며, waiver 가 없는 스캔은 전과 같은 문장을 출력합니다. 모든 검사가 끝난 스캔의 0.14.0 all-waived
  headline 은 바뀌지 않았습니다. (QA 2026-11-02 P3 #11)
- 서명되지 않은 artifact 에 대한 `db update` 의 안내는 하나뿐인 무해한 원인을 먼저 말합니다. 야간 발행은
  한 단계에서 태그를 푸시하고 다음 단계에서 서명하므로, 그 사이(수 초, 재시도까지 약 1분)에 pull 하면
  "not signed" 를 보게 되고 `--allow-unsigned` 로 안내됐습니다. 이제 publisher 가 방금 푸시했다면 1분 뒤
  재시도하라고 먼저 말하고, 그다음 mirror 절, 마지막에 opt-out 을 말합니다. `db update` 는 여전히 한 번만
  시도합니다. (QA 2026-11-02 P3 #21)
- `db build` 는 Photon OS 피드 파일을 일시적 실패에 대해 재시도하며, 첫 non-200 응답에 빌드 전체를
  실패시키지 않습니다. 이 provider 는 major 당 GET 을 한 번만 보냈고, 2026-10-17 야간 발행은 고정된 세
  `cve_data_photon<N>.json` URL 중 하나에 Photon CDN 이 돌려준 404 로 죽었으며 그 파일은 다음 날 밤
  돌아와 있었습니다. 이제 각 major 는 Fedora provider 가 쓰는 0.5s/1s backoff 로 최대 세 번 가져오며,
  429, 5xx, 다운로드 도중의 connection reset 이나 잘린 본문, 그리고 -- 이 세 URL 은 고정되어 있고 정상임이
  확인된 것이므로 Fedora 와 달리 -- 404 에 재시도합니다. 그 밖의 4xx, 취소, 온전한 본문의 decode 오류는
  여전히 즉시 실패하고, 정말 사라진 파일은 세 번 시도한 뒤 시도 횟수를 오류에 담아 실패합니다. 모든
  재시도는 빌드의 progress 출력에 URL, 실패 내용, 시도 번호와 함께 알립니다. Last-Modified 읽기는
  바뀌지 않았습니다.
- `--fail-on-eol` 로 실행한 스캔은 데이터베이스의 end-of-life 데이터가 생성된 지 7일이 넘으면 stderr 에
  날짜와 실행할 명령을 들어 경고합니다. `EOL_ENABLE=0` 인 ratings-only 빌드는 시드의 카탈로그를 시드만큼
  오래된 채로 물려받는데, D139 경고는 빌드 시각을 읽으므로 그런 데이터베이스가 최신으로 읽히면서 그 사이
  지원이 끝난 릴리스는 여전히 지원 중으로 판정됐습니다. exit 코드와 stdout 은 그대로이고, 플래그가 없거나
  데이터에 날짜가 없으면 아무 말도 하지 않습니다.
- 야간 발행과 backfill 은 digest 참조가 아닌 것은 서명하지 않습니다. Publish 단계가 `db push` 의 마지막 줄이
  `<repo>@sha256:<64 hex>` 꼴인지 확인하고, 서명·자가 검증 단계는 넘어온 step output 이 비어 있으면 cosign
  을 부르기 전에 종료합니다. 전에는 빈 output(이름이 바뀐 step id, 잘못 적은 output 이름)에 cosign 이 세 번
  실패한 뒤 잡이 "pushed and UNSIGNED" 라고, 아무것도 푸시되지 않은 이름에 대해 보고했습니다.
  `internal/ciguard` 가 이제 step output 을 `env` 로 넘기는 모든 단계에 그런 첫 줄 검사와, 같은 잡의 앞선
  단계가 그 output 을 쓰는지를 요구합니다.

## [0.14.0] - 2026-11-02

### Fixed
- 이미지 layer 하나 안에서 같은 경로의 마지막 항목을 스캔이 읽습니다. 나중 파일, 링크, 타입 변경, whiteout
  이 앞의 것을 대체하며, tar 를 풀었을 때 디스크에 남는 것과 같습니다. 전에는 첫 항목이 이겨서, 조작된 layer
  가 컨테이너가 실제로 쓰는 것과 다른 패키지 데이터베이스를 스캔에 보여줄 수 있었습니다. hardlink 는 여전히
  링크가 쓰인 시점의 대상을 가리킵니다(D130). (감사 2026-10-22 P4, 2026-11-02 재검증)
- 이미지 안의 심볼릭 링크 사슬을 Linux 자체 한도인 40개까지 따라갑니다. 전에는 7개였습니다. 그 뒤에도 링크인
  경로나 링크 순환은 읽지 못한 것으로 보고됩니다. JSON `unread[]`, SARIF `assay/not-read`, 표의 개수에 적히고
  target 의 불완전으로 세어 `--fail-on-incomplete` 와 `=target` 이 exit 2 가 됩니다. 전에는 없는 파일처럼
  보여 이미지가 distro 나 패키지가 없는 것처럼 보였습니다. **JSON 보고서의 `schemaVersion` 은 16** 입니다
  (추가형, 새 필드 없음). `unread[]` 가 이제 이미지 안의 경로도 적을 수 있고, 표의 개수는 "path(s) not read"
  로 읽힙니다. (감사 2026-10-22 P4, 2026-11-02 재검증)

- `db build --ratings-only --seed` 가 EOL source 가 설정되지 않았을 때(`EOL_ENABLE=0`) seed 의 end-of-life
  카탈로그와 enrichment record 의 provenance 를 유지합니다. 전에는 새 metadata 가 그 위에 덮어써져 EOL
  행이 사라지고, 그런 데이터베이스에서 `--fail-on-eol` 은 gate 대신 경고만 했으며, `db status` 는 enrichment
  를 data-as-of 없이 보여줬습니다. EOL source 가 설정되면 여전히 카탈로그를 대체합니다. `EOL_ENABLE=0` 줄은
  seed 의 카탈로그를 seed 만큼 오래된 채로 유지한다고 말합니다. (감사 2026-10-22 P4, 2026-11-02 재검증)

- NVD 가 rate limit 을 넘은 클라이언트에 답하는 HTTP 403 을 429, 5xx 와 같은 유한한 일정으로 재시도합니다.
  전에는 영구 실패로 보아, 한 번 throttling 된 페이지가 몇 시간 돈 sync 를 끝냈습니다. 풀리지 않는
  403(거부된 key, 차단된 주소)은 즉시가 아니라 일정을 다 쓴 뒤 여전히 실패합니다. (감사 2026-10-22 P4,
  2026-11-02 재검증)
- 주간 scanner differential 의 판정 step 이 fail-closed 가 됩니다. nightly publish gate 가 이미 그렇듯
  `exit ${{ steps.diff.outputs.exit_code || 2 }}` 입니다. step output 이 비면 bare `exit` 가 되어 0 을
  돌려주므로, step id 를 바꾸거나 output 이름을 잘못 치면 모든 주간 실행이 초록이 되고 고정 실패 이슈(D138)가
  닫혔을 것입니다. 이제 ciguard 테스트가 모든 workflow 의 `exit ${{ steps.<id>.outputs.<name> }}` 에 shell 이
  0 으로 줄이지 않는 nonzero fallback 이 있고, 그 output 을 쓰는 step 이 같은 job 안에서 먼저 선언되어 있는지
  확인합니다. (감사 2026-10-22 P4, 2026-11-02 재검증)

- `package-lock.json`(v1, v3), yarn v1 의 `yarn.lock`, `Cargo.lock`, `poetry.lock`, `uv.lock` 의 git,
  URL, 경로 의존성이 더는 그 체크아웃이 스스로 선언한 버전으로 카탈로그되지 않습니다. 그 버전은 권고문이
  가리키는 레지스트리 릴리스와 같다는 보장이 없어, 스캔이 오탐과 조용한 미탐을 모두 낼 수 있었습니다.
  이제 이런 항목은 평가되지 않음으로 집계되고 stderr 에 이름이 나옵니다
  (`not pinned: <lockfile>: <name> (<reason>)`). `pnpm-lock.yaml`, yarn berry, `Gemfile.lock`,
  `Pipfile.lock` 이 이미 하던 방식입니다. 체크아웃 자신이 가진 소스(uv 의 `editable` 프로젝트나
  워크스페이스 멤버, yarn v1 의 `file:`/`link:` 항목)는 pnpm 과 berry 의 로컬 항목처럼 이름만 보이고
  집계되지 않습니다. 대체 레지스트리나 사설 레지스트리는 그대로 카탈로그되며, `source` 가 없는 Cargo
  크레이트(워크스페이스 자신의 것)도 마찬가지입니다. `composer.lock` 은 바뀌지 않습니다. 평범한 Packagist
  패키지에도 `source.type = "git"` 을 기록하기 때문입니다. (감사 2026-10-22 P4, 2026-11-02 재확인)
- 한 advisory 의 여러 range 가 설치된 버전을 포함하면, 발견은 그 모두를 벗어나게 하는 fix 를 적습니다. 그
  가운데 가장 높은 fixed bound 이고, 열린 range 보다 bound 가 있는 range 를 우선합니다. range 는 합집합이라
  패키지는 자기를 포함하는 모든 range 를 벗어나야 affected 가 아니게 됩니다. 전에는 파일에서 첫 번째 range 가
  이겨서, 안내되는 fix 가 producer 의 순서를 따라 바뀌었습니다. Red Hat 과 SUSE CSAF provider 는 fixed build
  하나에 range 하나를 lexical 순서로 쓰고, 열린 range 가 먼저 나오면 fix 가 아예 가려졌습니다. 판정은 바뀌지
  않고 보이는 fix 와 `ratings[].fixed` 만 바뀝니다. bound 를 읽을 수 없는 range 가 그 뒤에서 버전을 포함하는
  range 를 더 이상 가리지 않습니다. 이제 skip 이 아니라 발견입니다. (감사 2026-10-22 P4, 2026-11-02 재검증)
- 설치된 버전과 순서를 매길 수 없는 advisory bound 는 패키지가 아니라 advisory 의 결함입니다. Composer 의
  `dev-master`, 그리고 SemVer 와 Bitnami 가 읽지 못하는 fixed/last_affected `"0"` 이 여기에 해당합니다. 전에는
  skip 이 "this package's own version could not be read" 라고 말하고 target 불완전으로 집계되어,
  `--fail-on-incomplete=target` 이 upstream 데이터 때문에 실패했습니다. (감사 P4, 2026-11-02 재검증)
- ignore 규칙이나 VEX statement 가 suppress 한 발견에 `--explain` 을 주면 그 발견을 설명합니다. 첫 줄에 판정에
  세지 않는다는 것과, 어느 waiver 가 왜 그랬는지를 적습니다. 전에는 식별자를 잘못 친 것처럼
  `no finding matches` 와 exit 2 로 답했습니다. 모든 발견이 waive 되면 표의 headline 도 깨끗한 스캔의 문장
  대신 그렇다고 말합니다("No unwaived vulnerabilities found ... N finding(s) suppressed, listed below").
  (감사 P4)
- 버전이 고정된 `requirements.txt` 패키지는 다른 Python reader 의 패키지처럼 purl(`pkg:pypi/<name>@<version>`),
  type, 파일 위치를 가집니다. 전에는 그 purl 을 지목한 VEX statement 가 "matched nothing" 경고도 없이 닿지
  않았고, JSON 보고서는 발견이 어느 파일에서 나왔는지 말하지 못했습니다. (감사 P4, 2026-11-02 재검증)
- SUSE: 문서에 빌드가 하나도 나열되지 않은 패키지의 `known_affected`(또는 not-affected, no-fix
  remediation) id 를 product id 로 저장합니다. 전에는 건너뛰었고, 그것이 문서의 유일한 진술이면 문서
  전체가 사라졌습니다. 2026-11-02 에 표본으로 뽑은 live 문서 688건에서 id 3,478개가 이렇게 버려졌고 문서
  142건은 record 를 하나도 내지 못했습니다. SLES 12 SP5 부터 16.x 와 그 Leap codestream 에 "affected,
  no fix" 항목 2,876개가 추가됩니다(MozillaFirefox, kernel, terraform, apache2 등). fix 버전은 바뀌지
  않습니다. `db build` progress 줄은 읽을 수 있는 purl 이 없는 SUSE leaf 도 찍습니다. 집계만 되고 한 번도
  보이지 않던 값입니다. 데이터베이스 변경이므로 merge 후 nightly 와 함께 `db update` 에 닿습니다.
  (D159, D126 개정, 감사 B2)

## [0.13.0] - 2026-11-02

### Changed
- Canonical 의 Ubuntu CVE tracker 가 tuple 하나 없이 파싱되거나, fix state 없는 Ubuntu range 어디에도 fix state
  를 stamp 하지 못하면 `db build` 가 실패하고, Ubuntu fix state 없이 일부러 빌드하려면
  `UBUNTU_TRACKER_ENABLE=0` 을 설정하라고 알려 줍니다. `db push` 는 어느 Ubuntu 릴리스든 공개된 fix state 의
  80% 미만만 가진 후보를 거부합니다. 건수는 DB 에서 셉니다(`--force` 로 넘길 수 있음). 이전에는 파싱을 멈춘
  tracker 가 Ubuntu 의 wont-fix 와 not-fixed state 를 모두 잃은 artifact 를 공개해도(2026-10-29 기준
  2,094,636 건) 아무것도 실패하지 않았습니다. (D157, D85 개정, 감사 A15)
- CVSS v2 벡터만 가진 평가(NVD 가 다시 채점하지 않은 모든 CVE 의 평가로, 2026-10-27 DB 에서 72,405 건)를,
  `unknown` 이던 것에서 v2 기본 점수로 NVD 의 v2 등급표(Low/Medium/High, Critical 없음)에 따라 등급을
  매깁니다. v2 는 같은 레코드에 점수를 낼 다른 것이 없을 때만 씁니다. unknown 이던 발견이 이제 등급을
  가질 수 있어 `--fail-on` 에 걸릴 수 있습니다. JSON 보고서의 `schemaVersion` 은 15(추가형)이며, 이렇게
  등급을 받은 평가에는 `"cvssV2": true` 가 붙고 `--explain` 은 `(CVSS v2)` 로 표시합니다. 발견의 평가는 이제
  점수보다 등급을 먼저 비교하므로 v2 High 가 다른 출처의 Critical 을 이기지 못하고, SARIF 의
  `security-severity` 는 발견의 등급 안에 머뭅니다. (D156, 감사 A14)

### Security
- 서명 키를 가진 job 이 태그만으로 고정된 코드를 더 이상 실행하지 않습니다. nightly publish 는 grype 를
  릴리스 tarball 로 받아 커밋된 sha256 으로 확인하고(이전에는 `curl get.anchore.io/grype | sh`), trivy 와
  goreleaser action 은 커밋으로 고정합니다. (감사 A18)
- 빌드는 go.mod 의 `toolchain` 줄을 하한으로 지킵니다. 지금은 `go1.26.10` 입니다. v0.12.0 은
  go1.26.9 로 빌드되었고, go1.26.9 에는 GO-2026-6809 (crypto/x509, go1.26.10 에서 수정)가 있습니다.
  `scripts/check-go-toolchain.sh` 는 하한보다 낮은 릴리스나 CI 빌드를 실패시킵니다. GoReleaser 의
  각 빌드는 무엇이든 게시하기 전에 자기 바이너리를 govulncheck 로 검사합니다
  (`scripts/release-vulncheck.sh`). (QA 2026-10-30)

### Fixed
- SARIF 출력이 카탈로거가 쓰지 못한 구성요소(버전 없음, purl 없음, 미지원 생태계)를 건수와 함께
  `assay/not-evaluated` 결과로 보고합니다. 이전에는 표가 평가되지 않았다고 말하는데도 GitHub code scanning
  에는 깨끗한 스캔으로 보였습니다. (D158, 감사 A16)
- 이미지 레이어가 패키지 데이터베이스, `os-release`, dpkg/pacman/Bitnami 레코드를 디렉터리, 장치, FIFO 로
  바꾸면, 실행 중인 컨테이너가 보는 대로 아래 레이어의 파일이 가려집니다. 이전에는 지워진 파일이 그대로
  읽혀 이미지에 없는 인벤토리가 보고되었습니다. 파일을 디렉터리로 바꾸면 `.wh.` 마커가 생기지 않아 whiteout
  규칙이 이를 잡지 못했습니다. (감사 A10)
- Gemfile.lock, Cargo.lock, uv.lock, requirements.txt 나 jar 의 pom.properties 에 64 KiB 가 넘는 줄이
  있어도 그 뒤의 패키지가 더는 사라지지 않습니다. 읽기 코드가 그 줄에서 오류 없이 멈추고, 스캔은 남은
  부분을 파일 전체로 보고했습니다(exit 0, 미완료 없음). (QA 2026-10-30)
- 범위가 open 두 개를 close 두 개보다 먼저 나열해도
  (`[introduced 1, introduced 3, last_affected 1, last_affected 3]`) 단일 버전 window 와 빈 window 를
  따로 판정합니다. 전에는 `[1, 3]` 으로 읽었습니다. (QA 2026-10-30, D154 개정)
- `db update` 와 `db build --seed` 는 HTTP/1 본문이 끊긴 경우처럼 다운로드 중 HTTP/2 스트림 리셋도
  재시도합니다. 취소되었거나 `--timeout` 을 넘긴 pull 은 더는 재시도하지 않습니다.
  (QA 2026-10-30, D140 개정)
- 중첩된 이미지 인덱스의 바깥 인덱스를 지목한 VEX 문장이 그 인덱스를 거쳐 선택된 이미지에
  적용됩니다. 레지스트리 대상과 `oci-dir:` 대상 모두 그렇습니다. (QA 2026-10-30, D121 개정)
- Alpine edge 이미지(`VERSION_ID=3.25.0_alpha20260805`)를 안정판 Alpine 3.25 의 advisory 로 판정하지 않고
  평가되지 않음으로 보고합니다. OSV 에는 edge 생태계가 없습니다. (감사 A11)
- 기본값이 아닌 `GOEXPERIMENT` 로 빌드한 Go 바이너리(`go1.26.7-X:fieldtrack`)의 stdlib 을 릴리스 버전으로
  카탈로그합니다. 이전에는 experiment 목록이 어떤 비교도 받아들이지 않는 prerelease 로 읽혀 stdlib advisory
  가 모두 건너뛰어졌습니다. (감사 A12)
- 한 패키지의 두 발견을 잇는 레코드로 발견이 합쳐질 때, apk provides 조인과 미러된 advisory 의 출처 표시가
  표시되는 레코드를 따라갑니다. (감사 A13, D10)
- `--fail-on-eol` 이 더 이상 하루 일찍 빨간불이 되지 않습니다. 릴리스가 EOLFrom 날의 첫 순간(그 날 KST
  09:00)부터 end of life 로 계산되었는데, D87 은 그 날을 아직 EOL 이 아니라고 약속합니다. 이제 다음 날부터
  EOL 입니다. 연장 지원도 마찬가지로 EOESFrom 날 전체를 덮습니다. 날짜는 UTC 입니다. 같은 비교를 하던
  `db build` 의 frozen 키 carry-forward(D110)도 이제 EOLFrom 다음 날부터만 EOL 이 지난 것으로 봅니다.
  (감사 A9, D87)
- 네이티브 gem 의 플랫폼(Gemfile.lock 의 `nokogiri (1.13.8-x86_64-linux)`, 또는 syft SBOM 의 gem 버전에
  들어간 같은 텍스트)을 더 이상 버전의 일부로 읽지 않습니다. 이전에는 x86_64 빌드에 대한 비교가 모두 불완전
  검사였고, 다른 빌드는 prerelease 로 정렬되어 설치된 버전에서 시작된 advisory 는 놓치고 그 버전에서 수정된 advisory
  는 오탐이 되었습니다. rails/rails 자신의 Gemfile.lock 에서 불완전 검사 130 건이 0 이 되었고, 놓치던 발견
  26 건이 보고되며 오탐 2 건이 사라졌습니다. purl 은 플랫폼을 유지합니다. (D155, 감사 A6)
- 뒤 창을, 그 창이 열리는 버전에서 닫히는 앞 창보다 먼저 적은 버전 range(`introduced 2.0, fixed 3.0,
  introduced 1.0, fixed 2.0`)는 뒤 창 안의 모든 버전을 깨끗하다고 판정했습니다. 이제 같은 버전에서는
  닫는 이벤트가 여는 이벤트보다 먼저 정렬되고, 한 버전에서 열리고 닫히는 창은 자기 경계로 따로 판정합니다.
  공개 데이터베이스에 이 모양의 레코드는 없었고, 동률을 가진 range 536 개를 각자의 경계에서 판정한 결과
  (2,892 건) 판정은 모두 그대로입니다. (D154, 감사 A7)
- rpm 배포판 이미지 스캔이 source 기준 advisory 를 바이너리가 아니라 source rpm 의 버전과 비교합니다.
  이전에는 자기 버전이나 epoch 를 가진 서브패키지가 다른 네임스페이스에서 판정되어, perl 의 서브패키지와
  npm 이 source 의 수정을 결코 통과하지 못했고(ubi9/perl-532 오탐 −342, ubi8/nodejs-18 −46), mod_ssl
  의 epoch 가 source 기준 피드에서 httpd 수정을 가릴 수 있었습니다. 쓸 수 있는 epoch 가 피드에 없는
  Azure Linux 와 Photon 에서는 source 버전에 epoch 를 붙이지 않습니다. (D153, 감사 A4)
- 일반 지원이 끝난 SLES 서비스 팩(12 SP5, 15 SP4–SP6 등 LTSS 트랙이 있는 것): SUSE가 mainline 제품을
  수정 없는 영향받음으로, SP-LTSS 제품을 수정됨으로 적을 때 LTSS 수정을 유지합니다. 이전에는 그 수정이
  버려져, 수정이 설치된 LTSS 이미지가 "영향받음, 수정 없음"으로 스캔되었습니다(2026-10-27 아카이브에서
  14,731개 항목). openSUSE Leap 결과는 바뀌지 않습니다. 데이터베이스 쪽 변경이라 병합 뒤의 야간
  빌드부터 `db update`로 전달됩니다. (D149, D91 수정)
- SPDX SBOM에서 `GENERATES` / `GENERATED_FROM` 관계로 source에 연결된 바이너리 rpm은 source
  이름으로 조회할 때 source의 버전으로 판정됩니다. 이전에는 npm을 nodejs의 수정 버전과 비교해
  (Red Hat CVE-2023-23920에서 수정된 npm에 대한 오탐), Fedora mod_ssl의 epoch이 httpd 수정을
  가릴 수 있었습니다. (D152, D143 수정)
- `install.sh`가 macOS에서 서명을 검증합니다. Apple base64가 거부하는 파일 인자를 더 이상 넘기지
  않으므로, 그곳에서 모든 정상 릴리스가 거부되던 문제가 사라졌습니다. (D151)
- 내려받지 못한 서명 페이로드(403, 404, 503)는 검증되지 않는 서명이 아니라 가져오기 실패로
  보고됩니다. `db update`는 그렇게 알리고 여전히 거부하며, 배포되는 `status.json`은
  `signed: false`를 표시하지 않고 마지막 관측을 유지합니다. (D150)

## [0.12.0] - 2026-10-27

### Added
- 이미지 스캔이 이제 stderr와 SARIF(규칙 `assay/inventory-scope`, note 수준)로, 이미지 안의
  애플리케이션 패키지(npm, Python, Java, Go 바이너리)는 검사하지 않았다는 점을 알려 주고,
  대신 무엇을 스캔해야 하는지 안내합니다. 종료 코드, 표, JSON은 바뀌지 않습니다. (D141)
- 데이터베이스가 7일보다 더 전에 빌드된 경우 스캔이 stderr로 경고합니다. 종료 코드와 stdout은
  바뀌지 않습니다. (D139)
- 나이틀리가 `status.json`(다이제스트, `builtAt`, `dataAsOf`, 서명 상태, 마지막 성공)을
  `status` 브랜치에 게시합니다. 실패 중인 운영 워크플로는 복구될 때까지 고정된 GitHub 이슈 하나를
  열어 둡니다. (D138)
- `assay db status --output json`이 테이블과 같은 사실을 자체 `schemaVersion`(1)을 가진
  JSON 문서 하나로 씁니다. (D147)
- `install.ps1`: PowerShell 5.1과 7용 Windows 설치 스크립트로, `assay.exe`를 설치하기 전에 릴리스
  체크섬 서명을 내장 키로 검증합니다. (D148)
- `SECURITY.md`(GitHub를 통한 비공개 제보), `CONTRIBUTING.md`, 이 변경 이력, 그리고 각 기계 판독용
  출력에서 `schemaVersion` 상향이 무엇을 뜻하는지 밝히는
  [`docs/compatibility.ko.md`](docs/compatibility.ko.md). 보고서 스키마 15부터는 JSON 보고서를 바꾸는
  모든 변경이 `schemaVersion`을 올립니다.

### Changed
- `db status`, `db ref`, `db build --seed <ref>`가 받지 않는 인자를 무시하지 않고 거부합니다
  (exit 2). (D147)
- `assay help`와 설계 문서가 스캔이 읽는 모든 타깃 종류와 락파일을 명시하고, DESIGN.ko.md의 범위
  절은 스캔이 다루지 않는 것을 나열합니다.
- CI 회귀 게이트: `az2023`과 `wolfi`에 실제 하한이 생겼고, 게이트가 `incompleteChecks`와
  `targetIncomplete` 개수도 타깃별 한도와 대조해 검사합니다. 새 타깃별 상한(`maxAssayOnlyFixed`)은
  수정 버전이 달린 assay 단독 finding을 제한합니다. 이 변경은 프로젝트 자체의 CI와 나이틀리 게이트에만
  해당하며 바이너리는 바뀌지 않습니다. (D145, D146)

### Fixed
- 이전 방식인 `.fips.N`과 `<digit>fipsN` 버전 표기를 쓰는 Ubuntu FIPS 호스트가 이제 평가하지 않음으로
  보고됩니다. 이전에는 메인라인 데이터로 판정되어 취약한 상태에서도 깨끗하게 스캔될 수 있었습니다.
  (D142)
- Red Hat의 SBOM 같은 SPDX SBOM에서 바이너리 rpm이 이제 `GENERATES` / `GENERATED_FROM` 관계에서
  소스 패키지를 가져오므로, Red Hat 권고가 `openssl-libs` 같은 패키지에 도달합니다. 이전에는 깨끗하다고
  보고했습니다. (D143)
- Oracle Linux에서, 같은 CVE를 두 ELSA가 고치는 비커널 패키지는 이제 버려지지 않고 자기 릴리스
  트레인의 가장 낮은 수정 버전으로 판정됩니다. openssh CVE-2024-6387, glibc CVE-2023-4911,
  389-ds-base CVE-2025-2487이 이제 매칭됩니다. Oracle Linux 지원(D74) 이후 어느 릴리스도 이들을
  매칭하지 못했습니다. 데이터베이스 쪽 변경이라 2026-10-26 야간 빌드부터 `db update`로 v0.11.0
  바이너리에도 전달됩니다. (D144)
- `db update`와 `db build --seed`가 스트림 중간에 끊긴 데이터베이스 레이어 다운로드를 최대 세 번까지
  재시도합니다. (D140)
- 데이터베이스를 빌드할 때 Ubuntu CVE 트래커의 `git fetch`가 중간에 잘린 응답을 재시도합니다.
  (D 번호 없음; PR #185)

## [0.11.0] - 2026-10-23

### Changed
- `db update`가 받아 온 내용이 이제 데이터베이스 안에 기록됩니다. `<dbPath>.artifact.json` 사이드카는
  더 이상 쓰이지 않으며, 기존 파일은 제거됩니다. (D127)

### Fixed
- 이미지의 하드링크가 그것을 만든 레이어의 파일로 해석됩니다. (D130)
- 접근할 수 없는 레지스트리가 패닉 대신 오류로 보고됩니다. (D 번호 없음; PR #168)
- 파싱할 수 없는 VEX 이미지 참조가 이제 모든 타깃에 적용되는 대신, 경고와 함께 어떤 타깃에도
  적용되지 않습니다. (D124)
- 매칭: npm 별칭이 실제 레지스트리 이름으로 매칭되고, 설치 경로는 JSON의 `locations[].install`에
  보존됩니다 (D132). Ubuntu와 RPM 계보 건너뛰기는 자기 생태계 안에서만 적용됩니다 (D133). 소스와
  이름이 같은 바이너리 패키지는 소스 버전으로 판정됩니다 (D134). `--fail-on-epss=NaN`은 플래그를
  파싱할 때 거부됩니다. 이전에는 게이트를 조용히 꺼 버렸습니다.
- SUSE 데이터: 업데이트 단계가 SUSE의 새 연도 접두사 레이아웃을 읽습니다. 놓치고 있던 여러 SUSE 패키지
  이름과 수정 버전이 이제 매칭되며, 여기에는 16,736개의 kernel-coco 빌드가 포함됩니다. SLE-Leap
  미러가 이제 Leap 자체의 진술을 존중합니다. 수정된 문서가 더 이상 오래된 레코드를 남기지 않습니다.
  (D122, D125, D126, D128, D129, D131, D135)
- openSUSE Leap 16.1이 이제 D108 미러를 통해 SLES 16.1 데이터를 받습니다. (PR #171)
- Red Hat은 업데이트를 적용하기 전에 전체 아카이브를 내려받습니다 (D135). NVD가 철회한 NVD 등급은
  데이터베이스에서 제거됩니다 (D136).

### Security
- 배포되는 데이터베이스가 cosign으로 서명됩니다. `db update`와 `db build --seed`는 아무것도 쓰기 전에
  바이너리에 내장된 키로 서명을 확인합니다. 서명되지 않은 데이터베이스는 `--allow-unsigned`를 주지
  않는 한 거부됩니다(`db update` 한정이며, `--seed`에는 예외가 없습니다). 검증되지 않는 서명은 항상
  거부됩니다. 미러는 `sha256-<digest>.sig` 태그를 함께 복사해야 합니다. (D137)
- 릴리스 체크섬이 서명되며, `install.sh`가 `openssl` 또는 `cosign`으로 서명을 확인합니다. 새 설치
  스크립트는 v0.10.0 이전 릴리스를 거부합니다. (D137)
- 모든 이미지 레이어가 끝까지 읽혀 그 파일을 사용하기 전에 다이제스트와 대조됩니다. `oci-dir:`와
  `docker-archive:` 이미지는 이전에 검증되지 않았습니다. 불일치하면 종료 코드 2입니다. (D123)

## [0.10.0] - 2026-10-13

### Added
- 모든 JSON 및 SARIF 보고서가 `provenance` 객체를 담습니다: 도구 빌드, 데이터베이스, 타깃, 모든 게이트
  설정, 모든 면제. 타임스탬프를 담지 않으므로 같은 입력은 여전히 바이트 단위로 동일한 보고서를
  냅니다. `--provenance <path>`는 인자 파싱 이후의 모든 종료 경로에서 실행 시각과 종료 코드를 담은
  사이드카 파일도 씁니다. `db update`는 이제 받아 온 내용을 기록하는 `<dbPath>.artifact.json`을
  씁니다. **(보고서 schemaVersion 14)** (D120)
- 이미지에서 발견한 OS 패키지(측정된 네임스페이스가 있는 배포판에 한하며, CleanStart는 제외)가 이제
  syft 방식의 purl을 가지므로 `--vex`가 이들에 도달합니다. 이미지를 지명한 VEX 진술은 그 이미지에만
  적용됩니다. `arch=src` 또는 `arch=source`로 표시된 소스 진술은 그 소스에서 빌드된 모든 바이너리를
  포괄합니다. **(보고서 schemaVersion 14)** (D121)

### Changed
- `--vex` 사용자 대상: VEX 문서가 해소하는 finding이 이제 이미지 OS 패키지에서 억제됩니다. 이미지를
  지명한 진술은 더 이상 다른 타깃의 finding을 억제하지 않습니다. (D121)

## [0.9.0] - 2026-10-13

### Added
- 레지스트리 이미지를 스캔할 때 이제 자격 증명을 사용하며, 시도 순서는 `ASSAY_REGISTRY_AUTH_*` 환경
  변수, docker 로그인, podman 로그인입니다. 자격 증명 값은 어디에도 출력되지 않습니다. 절반만 설정된
  자격 증명이나 깨진 docker 또는 podman 설정 파일은 종료 코드 2입니다. (D118)
- `--platform os/arch[/variant]`가 레지스트리, `oci-dir:`, `docker-archive:` 이미지에 대해 containerd와
  같은 방식으로 이미지 플랫폼을 고릅니다. 보고서는 스캔한 플랫폼과 다이제스트를 새 최상위 `image`
  객체에 기록합니다. **(보고서 schemaVersion 13)** (D119)

### Fixed
- 32비트 arm 호스트에서 기본 플랫폼이 인덱스의 첫 arm 항목 대신 `arm/v7`입니다. `arm64/v8`은 이제
  arm64 항목에 variant가 없는 인덱스와 일치합니다. 다른 인덱스 안에 중첩된 인덱스를 레지스트리에서
  받을 때 이제 동작합니다. (D119)

## [0.8.0] - 2026-10-12

### Added
- 프로바이더가 업스트림 생태계 키의 이름이 바뀌었음을 선언할 수 있습니다. 그러면 이전 키는 동결된
  채로 유지되는 대신 폐기됩니다. 첫 사례는 `Echo:PyPi` → `Echo:PyPI`였습니다. `db status`가
  `renamed:` 줄을 보여 줍니다. (D115)

### Fixed
- `db build`와 `db update`가 `<dbPath>.lock`에 운영체제 잠금을 겁니다. 두 번째 쓰기 프로세스는 첫
  번째와 조용히 경합하는 대신 즉시 종료 코드 2로 끝납니다. (D116)

### Security
- 파일당 512 MiB 한도보다 큰 jar는 인덱스를 읽기 전에 거부됩니다. 이전에는 조작된 아카이브가 메모리를
  무제한으로 쓸 수 있었습니다. (D112, 수정)

## [0.7.0] - 2026-10-07

### Added
- 읽기 상한: 이미지 레이어에서 읽는 파일마다, 그리고 SBOM마다 512 MiB, 이미지 스캔 전체에 2 GiB.
  상한에 닿으면 종료 코드 2로 끝나며 파일 이름을 밝힙니다. `--timeout <duration>`은 이미지 스캔을
  종료 코드 2로 멈춥니다. (D112)
- `--db-max-rating-age`가 NVD, EPSS, KEV 데이터의 나이를 따로 게이트합니다. (D113)

### Changed
- `--db-max-age`가 이제 스캔이 실제로 쓰는 데이터의 프로바이더만 판정합니다. 동결된 키는 동결일만큼
  오래된 것으로 칩니다. (D113, D59 수정)
- 나이틀리 데이터베이스는 게시되기 전에 주간 비교와 같은 회귀 하한으로 검사됩니다. (D114)

## [0.6.0] - 2026-10-01

### Added
- JSON 보고서에 스캔이 건드린 생태계 키마다 하나씩, 상태(`live`, `frozen`, `not-in-database`,
  `no-comparer`)를 담은 `coverage[]`가 생깁니다. `distro`와, 이미지 스캔의 경우 `inventoryScope`도
  추가됩니다. 표는 live가 아닌 모든 키를 나열합니다. SARIF는 `coverage`와 동결된 키마다
  `assay/frozen-data` 결과를 담습니다. **(보고서 schemaVersion 12)** (D111)
- 업스트림이 제공을 멈춘 릴리스 키는 사라지는 대신 유지되고 동결로 표시됩니다. 모든 출력 형식이 동결된
  키 아래의 finding을 동결일과 함께 보여 줍니다. (D110)

### Changed
- 읽을 수 없는 매니페스트가 `summary.targetIncomplete`에 계산되므로 `--fail-on-incomplete=target`이
  이때 종료 코드 2로 끝납니다. JSON에 `unread[]`가 추가됩니다.
  **(출시되지 않은 보고서 schemaVersion 11에서 추가됨; 처음 출시된 것은 12)** (D109)

## [0.5.1] - 2026-09-28

### Fixed
- `db push`가 이미 게시된 것보다 커버리지를 잃은 데이터베이스의 게시를 거부합니다(`--force`로
  우회). 같은 릴리스에 데이터베이스 빌드 수정도 포함됩니다: NVD가 시드의 창에서 재개하고,
  `--ratings-only`가 EPSS/KEV를 교체하며, Ubuntu 트래커 `git fetch`가 재시도합니다.
  (D 번호 없음; PR #135)
- 디렉터리 스캔이 이제 열지 못한 하위 트리를 읽지 못한 매니페스트로 보고하고,
  `--fail-on-incomplete` 아래에서 종료 코드 2로 끝납니다. 이전에는 깨끗하다고 보고했습니다.
  (D 번호 없음; PR #136)

## [0.5.0] - 2026-09-15

### Added
- openSUSE Leap 이미지가 자신이 빌드된 기반인 SLE 코드스트림의 권고를 상속하므로, SUSE가 피드에서
  Leap 릴리스를 내린 뒤에도 finding이 유지됩니다. 교차 매핑된 수정은 모든 출력 형식에 표시됩니다(JSON의
  `crossMappedFrom`, 선택 필드; 스키마 버전은 10 그대로). (D108)

## [0.4.1] - 2026-09-07

### Changed
- 성능: 심각도 점수 계산이 스캔 안에서 캐시되고, SARIF 규칙 도움말이 한 번만 만들어지며, PEP 440
  파싱이 빨라지고, 데이터베이스 빌드가 OSV 아카이브를 디스크에 스풀링합니다. 출력은 바이트 단위로
  동일합니다. (D 번호 없음)

### Fixed
- CISA KEV 가져오기가 이름 있는 `User-Agent`를 보냅니다. (D 번호 없음)

## [0.4.0] - 2026-08-30

### Added
- 대화형 터미널에서 표에 심각도 색상. `NO_COLOR`를 존중하며, 파이프로 넘긴 출력은 바이트 단위로
  동일합니다. (D107)

### Fixed
- Azure Linux / CBL-Mariner 데이터가 이제 Microsoft의 OVAL 피드에서 직접 옵니다. OSV.dev 사본은 3월부터
  동결되어 있었고, 누락된 140건의 finding이 모두 복구되었습니다. 직접 빌드한 데이터베이스에 해당하며,
  배포되는 데이터베이스는 이미 복구되어 있었습니다. (D106)

### Security
- 도달 가능한 표준 라이브러리 취약점 여섯 건을 고친 go1.26.7과 `klauspost/compress` v1.18.7로
  빌드합니다.

## [0.3.0] - 2026-08-28

### Added
- `pnpm-lock.yaml`과 yarn berry `yarn.lock`을 읽습니다. (D103)
- `--vex <path>`(반복 가능)가 OpenVEX 문서를 적용합니다. `not_affected`와 `fixed`만 finding을
  억제하며, 모든 억제에는 출처가 표시됩니다.
  **(보고서 schemaVersion 10: 억제된 레코드에 `source` 추가)** (D104)

## [0.2.0] - 2026-08-27

### Added
- `.assay.yaml`(또는 `--config`로 지정한 파일)의 무시 규칙. 사유는 필수이고 만료는 선택입니다. 면제된
  finding은 집계되어 모든 출력 형식에 표시되며 숨겨지지 않습니다.
  **(보고서 schemaVersion 9: `suppressed[]`, `summary.suppressed`)** (D102)

## [0.1.0] - 2026-08-27

### Added
- 첫 태그 릴리스. 이미지, Go 바이너리, 디렉터리, CycloneDX/SPDX SBOM에서 패키지 인벤토리를 만들고,
  assay가 직접 빌드하거나 받아 오는 데이터베이스(`db build`, `db update`)와 매칭합니다. KISA/KNVD
  한국어 권고 데이터가 일급 소스입니다. grype가 프로바이더를 제공하는 모든 OS 계열과 Bitnami 레이어,
  여덟 개 언어 생태계를 다룹니다. CI에 종료 코드 0, 1, 2를 줍니다. 출력은 표, JSON, SARIF입니다.
  **(보고서 schemaVersion 8; 저장소 스키마 9)** (결정 기록 D1–D101)

[Unreleased]: https://github.com/kun9497/assay/compare/v0.14.0...main
[0.14.0]: https://github.com/kun9497/assay/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/kun9497/assay/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/kun9497/assay/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/kun9497/assay/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/kun9497/assay/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/kun9497/assay/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/kun9497/assay/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/kun9497/assay/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/kun9497/assay/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/kun9497/assay/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/kun9497/assay/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/kun9497/assay/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/kun9497/assay/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/kun9497/assay/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/kun9497/assay/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/kun9497/assay/releases/tag/v0.1.0
