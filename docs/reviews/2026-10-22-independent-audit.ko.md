# 독립 전체 소스 감사와 서비스 제공 가능성 평가 — 2026-10-22

*[English](2026-10-22-independent-audit.md) · 한국어*

외부 리뷰가 검토한 것과 같은 커밋 `0164c94`(D131 머지)에 대해, 그 리뷰의 결함 6건을 고치는 작업
(PR #179, `docs/reviews/2026-10-22-source-review-response.md`)과 병렬로 돌렸다. 6건은 모든 에이전트에
이미 알려진 것으로 주고 제외했다. **이 문서의 어떤 것도 아직 고쳐지지 않았다**; 다음에 고칠 것의 목록을
근거와 함께, 가져가야 할 순서로 적은 것이다.

**방법.** 하위시스템마다 탐색 에이전트 하나, 각자 자기 git worktree 에서 하위시스템을 통째로 읽고 테스트를
돌리고 재현한 결함만(또는 솔직하게 "실행 안 함"으로 표시) 보고하라는 지시: source/image, OS 카탈로거, 언어
카탈로거와 SBOM 리더, 버전 comparer 와 range 평가, matcher, OSV/NVD/EPSS/KEV 프로바이더, CSAF/OVAL
프로바이더, store 와 `db` 명령, 스캔 판정과 렌더러, CI/릴리스/공급망. P1–P3 발견은 각각 독립 반박자 둘 —
정확성 관점(D 결정이나 기록된 보류에 따라 의도된 것인가?)과 재현 관점(실제 호출 경로에서 재현되는가?) — 에
넘겼고, 확신이 없으면 "반박"으로 기본값을 두게 했다. 두 반박자 모두 반박하지 못한 것만 **확인**이다. 별도
에이전트가 문서와 워크플로로 서비스 준비도를 평가했다. 에이전트 51개, 약 690만 토큰, 67분.

결과: **확인 18, 쟁점 2(반박자 의견이 갈림), 반박 0, 검증 없이 보고된 P4 16.** 반박 0 은 반박자보다
탐색자의 기준을 말한다: 탐색자는 가설을 올리기 전에 테스트로 반증을 시도하라는 지시를 받았다.

**상태 (2026-10-23).** A1 은 D142 로, A3 는 D143 으로 고쳐졌다.

## 1. 확인된 발견, 고쳐야 할 순서로

우선순위는 탐색자와 반박자가 합의한 딱지다(P1 = 주류 경로의 조용한 false negative; P2 = 조건부로 틀린
판정 또는 exit code; P3 = 눈에 보이는 증상이 있는 데이터 품질·견고성 결함). 같은 우선순위 안의 순서는 내
것이다: 실제 대상 몇 개에 닿는지 먼저, 수정 비용 다음.

| # | 우선 | 위치 | 결함 | 결과 | 근거(재현됨) |
|---|---|---|---|---|---|
| A1 | P1 | `internal/matcher/matcher.go:441` | `ubuntuLineageMarker` 가 `[~+](esm\|fips)[0-9]`; Canonical 의 16.04/18.04/20.04 FIPS 빌드는 `.fips.N`(`1.1.1f-1ubuntu2.fips.20`)으로 적힘. D53 skip 이 이들에게 절대 발화하지 않음 | dpkg 는 `fips` 를 빈 문자열 위로 정렬하므로 `…2.fips.12` 가 메인라인 fix `…2.18` 위에 옴: 20.04/18.04 FIPS 호스트에서 **finding 0, skip 0** — D53 이 막으려던 바로 그 방향 | `ubuntuLineageOf("1.1.1f-1ubuntu2.fips.12") = ""`; `Compare(...fips.12, ...2.18) = 1`; matcher 0/0. 라이브 OSV `UBUNTU-CVE-2024-0727` on `Ubuntu:Pro:FIPS-updates:20.04:LTS` |
| A2 | P1 | `internal/provider/oracle/oval.go:913` | `dropAmbiguous` 가 (CVE, major, package, stream) 그룹에 fixed EVR 이 둘 이상이면 기여자 전부를 버림. D74/D79/D81 은 이것을 kernel-UEK train 가드로 정당화하지만, 188,193 그룹 중 9,305 가 커널이 아니고 **9,305 전부가 RPM comparer 로 전순서** — 평범한 "el9_5 에서 고치고 el9_6 에서 다시 고침" 모양 | openssh(CVE-2024-6387), glibc(CVE-2023-4911), openssl-libs, curl, sudo, bash 와 약 1,500 개 Oracle Linux 패키지가 그 CVE 에 대해 **레코드가 아예 없음** | 라이브 2026-10-22 아카이브 측정: `non-kernel=9305 (distinct pkgs=1567, totally ordered=9305)`; `stored record for CVE-2025-2487 389-ds-base OL9: false` |
| A3 | P1 | `internal/cataloger/spdx/spdx.go:212` | Red Hat 자신의 SPDX 는 바이너리→소스 연결을 `GENERATED_FROM` 으로 이어진 별도 `?arch=src` 패키지로 적고, 바이너리 purl 에는 `upstream` 이 없음. 리더는 Source 를 `upstream` 에서만 읽고 src 패키지는 건너뛰므로 **Red Hat SBOM 의 모든 바이너리 rpm 이 `Source == nil`** | Red Hat 의 no-fix 항목 129만 건은 소스 이름으로 키되어 `Source.Name` 으로만 닿음: 벤더 SBOM 스캔은 `openssl-libs`, `krb5-libs`, `glibc-common`… 을 **깨끗하다** 고 하고, 같은 내용의 이미지 스캔은 찾아냄 | spdx probe `source=<nil>`; 이미지 경로 finding 1(wont-fix) vs SPDX 경로 0 |
| A4 | P2 | `internal/cataloger/rpmdb/header.go:243` | `Source.Version` 에 SRPM 이 아닌 **바이너리** EVR 을 채움(`pkgmeta.SourceRPMVersion` 이 있는데 안 씀). Fedora Bodhi, Photon, Azure Linux OVAL 은 소스 NVR 만 저장 | epoch/version 이 SRPM 과 다른 서브패키지는 namespace 를 가로질러 비교됨: `httpd 2.4.x` 에서 나온 Fedora `mod_ssl 1:2.4.x` 가 엉뚱한 카운터로 판정(위면 조용한 FN, 아래면 FP: `perl-*`, `device-mapper-*`) | rpmdb probe `mod_ssl: Version="1:2.4.62-1.fc40" Source={httpd 1:2.4.62-1.fc40}`; matcher probe 가 엉뚱한 카운터의 판정을 보임 |
| A5 | P2 | `internal/provider/suse/csaf.go:917` | D91 의 LTSS tie-break 가 같은 (키, 패키지)의 메인라인 항목이 있으면 LTSS 항목을 버림, shadow 가 fix 대 fix 라는 전제로. EOL 이후 문서는 EOL 된 제품을 `known_affected`(fix 없음)에 남기고 LTSS `recommended` fix 옆에 둠 | fix 인 `php8-8.2.35-150600.3.39.1` 이 설치된 SLES 15 SP6-LTSS 이미지가 **affected, no fix available** 로 보고됨; 최근 400 문서에 그런 모양 167 | 400 문서 probe: `167 LTSS FIXED, mainline NO-FIX -> fix lost` |
| A6 | P2 | `internal/cataloger/gemlock/gemlock.go:144` | `nokogiri (1.13.8-aarch64-linux)` 가 플랫폼 접미사를 버전에 남김; Gem comparer 는 하이픈을 프리릴리스로 읽거나(`1.13.8.pre.aarch64…`, 1.13.8 아래) 밑줄이 있으면 거절 | 네이티브 gem: 설치 버전에서 introduced 된 advisory 는 **finding 도 skip 도 없음**; 거기서 fixed 된 것은 false positive; `x86_64-linux` 변종은 파싱 불가로 skip | `Gem.Compare("1.13.8-arm64-darwin","1.13.8") = -1`; `"1.13.8-x86_64-linux"` → error |
| A7 | P2 | `internal/version/rangeeval.go:246` | `sortEvents` 가 버전으로만 정렬; 한 창의 `fixed`/`last_affected` 와 다른 창의 `introduced` 가 같은 버전으로 동률이면 파일 순서가 이기므로, 순서가 어긋난 range 는 같은 버전에서 창을 열고 닫음 | 둘째 창 안의 모든 버전이 빈 Evidence 로 **깨끗** 판정; 같은 이벤트를 정렬하면 affected(OSV 는 정렬을 요구하지 않고, 프로젝트 자체 테스트도 그렇게 말함) | probe: `fixed` 와 `last_affected` 모두 `v=2.0.5 sorted=true unsorted=false` |
| A8 | P2 | `.github/scanner-diff-targets.json:118,128` | `az2023` 과 `wolfi` 바닥이 `minAgree 0 / minFindings 0`, 2026-08-28 시딩 때 남은 값; `comparison.md` 는 오늘 83 과 12 의 일치를 기록 | Amazon Linux 2023 이나 Wolfi 매칭을 **전부** 잃은 후보가 D114 나이틀리 게이트와 주간을 `ok` 로 통과 — 게이트가 존재하는 이유인 D90 모양 | 매칭을 0 으로 만든 scandiff 런: `az2023 0 83 0 … ok`, `wolfi 0 83 0 … ok`, exit 0 |
| A9 | P2 | `internal/scancmd/eol.go:140` | 00:00 UTC 날짜로 `st.EOL = now.After(eolDate)` 라 EOLFrom 날의 첫 나노초부터 EOL; D87 과 필드 자신의 주석은 경계가 배타적(다음 날)이라고 약속 | `--fail-on-eol` 이 **하루 일찍** 빨강(EOLFrom 날 09:00 KST 부터); `eoesUnexpired` 도 같은 모양 | 런: 2026-01-01T00:00:00Z 에 `exit=1`, `EOL: alpine 3.19 reached end of Security Support on 2026-01-01` |
| A10 | P3 | `internal/source/walk.go:323` | 상위 레이어의 원하는 경로에 있는 비정규 엔트리(디렉터리, 디바이스, FIFO)는 질의에 답하지도 닫지도 않음; `hiddenFrom` 은 `<name>/` 접두어만 맞추므로 파일→디렉터리 교체(`<name>/` + `<name>/.wh..wh..opq`, `.wh.<name>` 없음)가 `<name>` 을 숨기지 못함 | 삭제된 하위 레이어의 패키지 DB 나 `os-release` 를 읽음: 증상 없는 **낡은 인벤토리**. `FilesUnder/Named/Matching` 도 같은 틈. assay 가 묻는 경로에서는 드문 모양 | probe: TypeDir, TypeChar, TypeBlock, TypeFifo 에서 `present=true data="OLD-DB" diff=sha256:base` |
| A11 | P3 | `internal/pkgmeta/distro.go:684` | Alpine edge 의 실제 `VERSION_ID` 는 `3.21.0_alpha20240807`; 첫 두 점에서 잘라 `Alpine:v3.21` 로 키함. 거절 테스트는 edge 가 절대 쓰지 않는 `3.21_alpha…` 철자 | `alpine:edge` 이미지가 거절되는 대신 안정 릴리스의 advisory 로 판정됨 | probe 가 `Alpine:v3.21` 로 키함 |
| A12 | P3 | `internal/cataloger/gobinary/goversion.go:59` | 기본이 아닌 `GOEXPERIMENT` 로 빌드된 바이너리는 `go1.26.7-X:fieldtrack`(하이픈, 릴리스 툴체인)으로 찍힘; 정규화기가 접미사를 semver 프리릴리스로 받아들임 | stdlib 이 `1.26.7-X:fieldtrack` 으로 카탈로그되고 comparer 가 거절: 모든 stdlib advisory 가 판정 대신 skip | probe 가 카탈로그된 버전과 skip 을 보임 |
| A13 | P3 | `internal/matcher/matcher.go:1289` | `absorb()` 가 흡수된 그룹의 승자(`Advisory`, `Evidence`, `MatchedName`, 심각도)는 옮기지만 `CrossMappedFrom`, `MatchedViaProvides`, `FrozenSince` 는 아님; `beats()` 교체는 셋 다 옮김 | 합쳐진 finding 이 엉뚱한 조인이나 미러 출처를 밝힘 — 판정 변화가 아닌 D10 설명 가능성 결함 | 합친 뒤 불일치를 probe 가 보임 |
| A14 | P3 | `internal/provider/nvd/parse.go:78` | CVSS v2 벡터만 가진 레코드는 저장되지만(`CVSS_V2`) `severity.Of` 는 `CVSS:3.`/`CVSS:4.` 만 점수화 | NVD 가 재채점하지 않은 2015년 12월 이전 CVE 전부가 NVD 출처에 들어가고도 `unknown` — rated 로 세어지고 band 는 없음 | probe: v2 만 있는 rating 의 `severity.Highest` = Unknown/0 |
| A15 | P3 | `internal/provider/osv/ubuntu_fixstate.go:207` | 튜플 0 개로 파싱되는 tracker clone(레이아웃 변경, 헤더 철자 변경)이 진행줄 하나와 함께 받아들여짐; 빌드도 게시 게이트도 실패시키지 않음 | 모든 Ubuntu wont-fix/not-fixed 상태가 아티팩트에서 조용히 사라짐 | probe: 빈 tracker → `stamped 0`, 빌드 계속 |
| A16 | P3 | `internal/report/sarif.go:89` | SARIF `not-evaluated` 결과는 matcher 의 skip 에서만 나옴; **카탈로거**가 패키지로 만들지 못한 컴포넌트(PURL 없음, 버전 없음, 미지원 생태계, 손상된 rpm 헤더)는 결과를 내지 않음 | 표는 N 개 not evaluated 라는데 GitHub code scanning 은 깨끗한 스캔을 봄 | 그런 스캔의 SARIF: `assay/not-evaluated` 결과 없음, invocation notification 만 |
| A17 | P3 | `cmd/scandiff/normalize.go:66` | scandiff 가 `summary.notEvaluated` 만 읽음; `incompleteChecks` 와 `targetIncomplete` 는 안 읽음 | 경계 파싱이 멈춘(모든 검사가 incomplete) 후보 데이터베이스가 게이트에서 신뢰할 만하다고 판정됨 | normalize.go 는 세 필드를 읽고 run.go 는 하나만 넘김 |
| A18 | P3 | `.github/actions/setup-scanners/action.yml:38` + `deferred-decisions.md` "Signing" | 서명 보류의 재검토 계기("제3자의 `db update` 가 이 레지스트리를 기본으로 신뢰하는 순간")가 2026-08-28 패키지 공개와 `DefaultRef` 의 신뢰로 이미 발화; 게시 잡은 `packages: write` 옆에서 고정되지 않은 `curl \| sh` 설치기와 태그로 고정된 액션을 돌림 | 모든 고객이 받는 아티팩트가 서명되지 않았고, 그것을 push 하는 잡이 가변 태그로 고정된 제3자 코드를 실행 | 워크플로 본문; `pull.go:25` |

**쟁점(반박자 의견이 갈림):**

| | 위치 | 주장 | 의견 차이 |
|---|---|---|---|
| B1 | `internal/cataloger/cyclonedx/cyclonedx.go:173` | syft 는 Go 툴체인을 `pkg:golang/stdlib@go1.21.0` 으로 적음; 어느 SBOM 리더도 정규화하지 않아 stdlib 이 읽을 수 없는 것으로 skip 되고 스캔이 target-incomplete | 정확성 반박자는 실제 P2 틈이라 함(gobinary 는 같은 문자열을 정규화); 재현 반박자는 skip 이 보이고 `--fail-on-incomplete=target` 이 걸리므로 — 조용하지 않고 시끄러움 — P4 로 봄 |
| B2 | `internal/provider/suse/csaf.go:483` | product_version leaf 가 없는 bare `known_affected` id 가 D126 이 어차피 bare id 를 product_id 로 이름 짓는데도 버려짐(`skipUnknownPackage`); 최근 400 문서에서 유일한 "affected, no fix" 진술 503 건 손실(SLES 15 SP7, 16.0) | 한 반박자는 정보 없이 데이터만 잃는 D126 후속으로 봄; 다른 반박자는 leaf 요구를 잘못 키된 id 에 대한 문서화된 가드로 보고, 완화 시 false positive 수가 측정되기 전까지 P4 |

**검증 없이 보고된 P4**(볼 가치는 있으나 근거는 아님): 한 레이어 tar 안의 중복 경로(첫 것이 이김, 추출은
마지막); 8 홉을 넘는 symlink 체인이 조용히 없음; D119 의 arm64→arm 비폴백 대 containerd 의 `platforms.Only`;
`alpine:edge` 키(위 P3 와 같은 것, 두 번 제출됨); lockfile 의 git/fork 의존성이 fork 가 선언한 버전으로
카탈로그됨; `requirements.txt` 패키지에 PURL/Type/Location 없음(VEX 가 닿지 못함); 길이가 다른 전부-0 점
컴포넌트에 대한 apk comparer; 순서 지을 수 없는 경계를 패키지 탓으로(`CauseTargetVersion`); 첫 히트
Evidence 가 엉뚱한 range 를 댐; NVD 403 rate-limit 응답을 영구로 분류; SUSE `SkippedNoPurl` 은 세지만
절대 안 찍힘; EOL 출처가 없을 때 `--ratings-only` 가 seed 의 EOL 카탈로그를 버림; 면제된 finding 에
`--explain` 이 "no finding"; 모든 finding 이 면제됐을 때 표 헤드라인이 "No known vulnerabilities"; SUSE
`upstreamvectors` 테스트가 CI 에 없음; 주간 차분의 fail 스텝에 나이틀리의 fail-closed 폴백이 없음.

## 2. 서비스 제공 가능성 평가

준비도 에이전트는 `CLAUDE.md`, `README.md`, `docs/DESIGN.md`, `docs/deferred-decisions.md`,
`docs/comparison.md`, `docs/integrations.md`, 로드맵의 D28/D58/D59/D110/D114/D120, 워크플로 다섯 개 전부,
릴리스 설정과 설치기, pull/scan 코드 경로를 읽었다. 그 결론을 나는 인용된 근거를 읽고 나서 공유한다:
**스캔 코어는 석 달 된 프로젝트로서는 이례적으로 잘 검증돼 있고, 게시 아티팩트 파이프라인은 대부분의 상용
스캐너가 드러내는 것보다 많은 자기 검사를 갖고 있다; 오늘 판매할 수 없는 이유는 대체로 코드 주변에 있다.**
다섯 가지 틈과 에이전트가 제안한 가장 싼 신뢰할 만한 처방:

1. **아무것도 서명되지 않았고 누가 데이터베이스를 만들었는지 아무도 검증할 수 없다.** 바이너리는 sha256
   체크섬만(cosign 없음, SLSA provenance 없음, SBOM 없음); 아티팩트는 pull 때 digest 검증되지만 서명이
   없고, 보류 항목 자신의 재검토 계기가 이미 발화했다(A18); `install.sh` 는 `main` 에서 고정되지 않은
   `curl | sh`; `dependabot.yml` 없음, `SECURITY.md` 없음. 처방: `release.yml` 과 `db-publish.yml` 의
   `db push` 뒤에 cosign keyless; `pull.go` 에 실패 시 exit 2 하는 `cosign.Verify` 단계(에어갭 미러용 명시적
   skip 포함); 설치기를 태그에 고정; dependabot 과 보안 정책 추가.
2. **아무도 호출받지 않고, 수동 단계가 critical path 에 있다.** 어느 워크플로에도 알림 단계 없음(2026-08-04/05
   나이틀리 둘이 조용히 실패); 스키마 bump bootstrap 은 손으로 도는 로컬 빌드와 push; 월요일 re-banding 은
   수동; 레지스트리는 개인 namespace 아래; `db update` 는 재시도도 폴백도 없고 고객은 늙어가는 날짜만 본다.
   처방: 고정 이슈를 열거나 갱신하거나 webhook 에 올리는 `if: failure()` 단계; 게시되는 `status.json`(마지막
   정상 digest, data-as-of, 게이트 결과); bootstrap 을 `workflow_dispatch` 잡으로; advisory 데이터가 7일
   넘게 오래됐을 때 기본 stderr 경고; `Pull` 에 3회 재시도; org namespace.
3. **이미지 안의 애플리케이션 패키지가 조용히 없다(D70).** exit 0, finding 0, 표와 SARIF 에 공개 없음; 차분
   대상 셋에서 Critical 누락 측정됨. 처방: 보류 항목 자신의 "S" 옵션을 지금 출시(모든 이미지 스캔에 stderr 한
   줄과 SARIF `assay/inventory-scope` notification), 그 다음 항목이 이미 크기를 잰 고정 위치 탐침.
4. **차별점을 서비스로 전달할 수 없다.** D29 가 모든 아티팩트에서 KISA 를 벗김; 한국어 산문을 원하는 고객은
   `git` 과 모든 업스트림이 닿는 상태에서 몇 시간짜리 `db build` 를 직접 돌려야 한다. 처방: 라이선스 해결(사업
   결정), 안 되면 advisory 와 rating 을 그대로 seed 하고 KNVD 만 가져오는 `db build --enrichment-only --seed
   <ref>`(몇 분, `git` 불필요).
5. **프로젝트 자신의 규칙이 구멍이 생긴다고 말하는 곳에 검증 구멍이 있다.** SUSE 라이브 피드 테스트는
   `upstreamvectors` 태그가 붙어 CI 가 절대 돌리지 않음(`ci.yml` 이 경고하는 "coverage 로 세어지고 절대
   실행되지 않는" 모양); CI 는 `ubuntu-latest` 뿐이라 Windows 태그 테스트는 절대 안 돎; `comparison.md` 에
   분류되지 않은 assay 전용 튜플(wolfi 34, mariner2 53, ubuntu 38)이 고객에게 나가는 false positive 후보;
   게이트는 설계상 회귀만. 처방: SUSE 태그 런을 CI 에 추가; `-race` 없는 `windows-latest`/`macos-latest`
   매트릭스; 분류 잡과 대상별 `maxAssayOnly` 상한으로 D117 이후 grype 전용 증가가 그러듯 FP 증가가 주간 런을
   걸게 함.

첫 고객 전에 할 싼 항목들: `cmd/assay/main.go` usage 와 `DESIGN.md` §Usage 가 낡음(여전히 "go.mod alone",
"Go, npm, PyPI, Alpine"); `DESIGN.md:75-76` 이 여전히 "개인 프로젝트 — 운영에서는 기존 스캐너를 쓰라";
`CHANGELOG.md`, `SECURITY.md`, `CONTRIBUTING.md`, JSON 스키마 호환성 선언 없음(`schemaVersion` 이 3주에
10→14); `db status` 에 `--output json` 없고 `db` 는 모르는 플래그를 무시; 설치기에 Windows 경로 없음; 문서화된
CI 캐시 키가 업그레이드를 살아남음.

오늘 고객에게 말해야 하는 것(에이전트의 §6, 보류 기록과 일치): D70 애플리케이션 패키지; 동결된 지원 종료
데이터(Debian 11); Ubuntu ESM/FIPS 와 Oracle Ksplice/FIPS 는 평가 안 함, RHEL EUS/AUS/E4S 는 메인라인으로
판정; 아티팩트에 KISA 없음; CPE/NVD 폴백 matcher 없음; 런당 플랫폼 하나, Docker 데몬 소스 없음,
`syft:distro:*` 없는 SBOM 은 OS 패키지를 못 맞춤; 언어 생태계 여덟; `MAL-*` 제외.

## 3. 평가와 권고 순서

**감사에 대해.** P1 셋은 주류 입력에서의 조용한 false negative 이므로 먼저, 이 순서로: A1(정규식 하나와
Canonical 철자 측정 — 몇 시간), A3(SPDX 리더에서 `GENERATED_FROM` 읽기 — 하루), A2(일괄 모호성 드롭을
"그룹이 전순서가 아닐 때만 버리고 아니면 최고값 유지"로 교체 — 하루 더하기 라이브 아카이브 재측정과 차분
런, Oracle Linux 에 레코드가 늘어나므로). 그 다음 실제 대상의 판정을 바꾸는 P2: A5(SUSE LTSS, 400 문서에
167 모양), A4(Fedora/Photon/Azure 키가 의존하는 rpm SRPM 버전), A7(`sortEvents` 의 tie-break, 작고
위험함), A6(gem 플랫폼 접미사), A8 과 A17(게이트 바닥과 scandiff 요약 읽기 — 가장 싸고 나머지 전부를
보호함), A9(비교 하나). P3 들은 릴리스 하나 분량의 작은 작업이고, A18 은 아래 준비도 목록의 첫 항목이다.
각 수정은 PR #179 의 6건과 같은 규율을 따라야 한다: 실제 호출 경로의 실패 테스트, 수정, 변이 라운드, 양국어
문서, 그리고 발견이 라이브 데이터를 인용하면 그 측정.

**준비도에 대해.** 에이전트의 결론에 동의한다. 코드가 그 주변의 운영보다 나은 상태다. 유료 서비스로 제공하기
전에 나는 이 순서로 하겠다: (1) 바이너리와 아티팩트 서명 더하기 검증하는 pull(틈 1, A18 도 닫힘); (2) 실패
알림과 공개 신선도 신호(틈 2); (3) 모든 이미지 스캔에 D70 공개 줄 — 가장 큰 알려진 맹점을 시끄럽게(틈 3);
(4) 위의 P1 셋; (5) CI 구멍(틈 5)과 게이트 바닥(A8, A17); (6) 문서 항목 — 싸고, 고객이 먼저 읽는 것. KISA
문제(틈 4)는 제품이 내세우는 차별점을 좌우하는 사업 결정이라 병렬로 정리해야 한다.

위의 모든 것은 제안이다. 이 문서의 어떤 것도 코드에서 바뀌지 않았다.

## 다시 돌리기

에이전트별 기록과 각 발견의 재현은 워크플로 journal(`wf_fbadf3f4-a84`, 그것을 돌린 세션에 국한)에 있다.
확인된 각 행의 "근거" 열은 반박자가 관찰한 probe 출력을 인용한다; probe 는 격리된 worktree 에서 `0164c94`
에 대해 쓴 일회용 테스트이고, 행의 설명만으로 재현할 수 있다.
