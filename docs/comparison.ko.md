# assay · grype · trivy — 비교

*기능 열은 2026-08-27 시점 스냅샷 — assay v0.2.0, grype v6, 그리고 그날 읽은 trivy.dev
문서 기준. 패리티 표의 assay↔grype 수치는 assay v0.8.0, grype v0.116.1, trivy v0.74.0
대상의 **2026-10-12 주간 실행**(GitHub Actions run 38187900074)으로 갱신한 **실측값**입니다:
같은 digest 고정 이미지를 두 스캐너에 넣는 주간 차등(D93)의 결과이며, 튜플 수는 도구의
정규화를 거친 값입니다. trivy 열은 2026-08-27 시점 공식 문서 기준의 **스펙 비교**로
남아 있습니다 — trivy는 D105에서 주간 차등에 합류했으며 지금은 25개 타깃 중 18개에서
실행됩니다. 행별 trivy 수치는 원래 날짜를 유지합니다.*

## 구조와 성격

| | grype 생태계 | trivy | assay |
|---|---|---|---|
| 형태 | 세 프로젝트: syft(인벤토리), vunnel + grype-db(데이터베이스), grype(매칭) | 멀티 스캐너 하나: 취약점 + 설정 오류(IaC) + 시크릿 + 라이선스 | 취약점 전용 바이너리 하나: 인벤토리 → 매칭 → 판정 |
| 데이터베이스 | 별도 도구가 빌드·게시 | 기본값이 스캔 시 자동 다운로드 — 편리하지만 스캔 경로에 네트워크가 들어오고, 에어갭은 별도 오프라인 절차 필요 | `assay db update`가 명시적으로 당겨오고 스캔은 **절대** fetch하지 않음(D14) — SBOM·로컬 타르볼 스캔은 네트워크 호출 0회 |

## 커버리지

| 영역 | assay | grype | trivy | 비고 |
|---|---|---|---|---|
| OS 패밀리 공통부 | ✓ | ✓ | ✓ | Alpine·Debian·Ubuntu·RHEL·Rocky·Alma·Amazon·Oracle·SLES/Leap·Wolfi·Chainguard·MinimOS·Echo·Azure Linux·Photon — 셋 다 커버 |
| Fedora · Arch | ✓ (D75, D97) | ✓ | ✗ | trivy 지원 목록에 둘 다 없음 (CentOS Stream도 명시적 미지원) |
| Alpaquita · Hummingbird · CleanStart | ✓ (D95, D98, D101) | 일부만 | ✗ | grype는 Hummingbird 프로바이더 보유; Alpaquita·CleanStart는 assay 단독 |
| openSUSE Leap · SLE | ✓ | ✗ v6에 데이터 없음 | SLE ✓, Leap은 실측 공백 | SLE BCI에서 trivy는 실재하되 다른 어휘를 씁니다: finding을 SUSE-SU 패치 advisory로 키 잡고 CVE는 References URL 안에만 실어, D105 첫 측정이 "trivy가 아무것도 못 찾았다"로 오독됐다가 차등이 그 CVE를 추출하도록 배우고서야 바로잡혔습니다(추출 후 assay와 agree 182/188). Leap 15.6 이미지에서는 trivy가 진짜로 빈 취약점 목록을 반환하며(릴리스를 EOSL로 표시) assay는 12건을 보고 — 이 타깃은 정보 모드 유지 |
| Bottlerocket · CoreOS | ✗ | ✗ | ✓ | trivy 단독 |
| 언어 생태계 | 8종 | 8종 | 더 넓음 | 공통 8종(Go·npm·PyPI·crates.io·Maven·RubyGems·NuGet·Packagist); 셋 다 pnpm과 yarn berry 락파일을 읽습니다(assay는 D103부터); trivy는 여기에 더해 Conan·Dart·Swift·Elixir까지 다룹니다. assay는 이 8종을 대상으로 지정된 디렉터리·락파일·jar·Go 바이너리에서만 읽으며 — **컨테이너 이미지 내부에서는 읽지 않습니다**(D70, 미룸). grype는 이미지 안에 설치된 언어 패키지를 카탈로그화하고(측정: 아래 SLES·RHEL 행), trivy 문서는 이미지 대상에 대해 이를 다룬다고 명시합니다 — 다만 차등이 호출하는 방식으로 돌리면 trivy는 두 이미지 모두 OS 결과만 돌려주어 어느 쪽도 뒷받침하지 않습니다 |
| 보강 피드 게이트 | NVD · EPSS · KEV · EOL | NVD · EPSS · KEV · EOL | 내장 없음 | trivy는 심각도 중심 — EPSS/KEV/EOL을 게이트로 내장하지 않음 |
| KISA / KNVD | ✓ 1급 소스 | ✗ | ✗ | assay가 기존 도구 재사용 대신 존재하는 이유 |
| 취약점 외 스캔 | ✗ (의도) | ✗ (의도) | 설정오류 · 시크릿 · 라이선스 | trivy는 멀티 스캐너 — 격차가 아니라 범위의 차이 |

## 실측 패리티 — 패밀리별, 수치는 2026-10-12 주간 실행

같은 digest 고정 이미지를 두 스캐너에 넣고 튜플 단위로 비교했습니다 — 2026-08-24에
13개 타깃으로 처음 측정했고, 지금은 25개 타깃으로 매주 실행되며 그중 18개에는
trivy가 함께합니다(D105, D114). 2026-08-28에 전체를 다시 감사했습니다(한쪽에만 있는
튜플을 전부 분류했고, 감사 기록은 deferred-decisions에 있습니다). **결과** 열은
2026-10-12 주간 실행의 수치(일치 / assay-only / grype-only)이고, **차이의 원인** 열은
2026-08-28 감사의 분류를 유지하며, 수치가 이번 실행보다 오래된 곳에는 날짜를 붙였습니다 —
수치는 그 뒤로 움직였지만 분류를 다시 하지는 않았습니다. trivy가 한쪽을 뒷받침하는 경우
해당 행에 표시했습니다.

| 패밀리 | 결과 | 차이의 원인 | 판정 |
|---|---|---|---|
| Alpine | 10건 일치, assay-only 0, grype-only 4 (alpine319) | grype의 +4는 CPE 폴백 매처 산출 — assay가 의도적으로 갖지 않는 것 (2026-08-24 분류) | 완전 일치 |
| Ubuntu | 168건 일치, assay-only 38, grype-only 0 (ubuntu2204) | assay-only가 5건(2026-08-28 감사에서는 grype에 없는 최신 USN)에서 이번 실행에서는 38건으로 늘었고, 38건은 재분류하지 않았습니다. wont-fix 17/17(CVE 10건 기준)은 2026-08-28에 정확히 일치했고(D85) 이번에는 다시 측정하지 않았습니다 | assay 우세 |
| AlmaLinux | 202건 일치, assay-only 1, grype-only 592 (alma9) | 592건은 OS 타입 튜플입니다. 2026-08-28에는 fixable 집합이 동등(110/0/0)했고 당시 grype의 512건 추가분은 전부 Alma 대신 대입된 Red Hat 데이터의 not-fixed/wont-fix였습니다. fixable 한정 수치는 2026-10-12 기준으로 다시 도출하지 않았습니다 | fixable 기준 완전 일치 (08-28) |
| Amazon Linux 2023 | 83건 일치, assay-only 0, grype-only 1 (az2023) | 2026-08-28 감사의 0 = 0은 더 이상 성립하지 않습니다; 하나뿐인 grype-only 튜플은 분류하지 않았습니다 | 거의 일치 |
| Wolfi | 12건 일치, assay-only 34, grype-only 44 (wolfi) | 2026-08-28 감사의 0 = 0은 더 이상 성립하지 않습니다(assay 46, grype 56); 양쪽 추가분 모두 아직 분류하지 않았습니다 | 미분류 |
| Debian | 242건 일치, assay-only 5, grype-only 0 (debian12) | 2026-08-28에는 당시 assay-only 6건이 grype DB 누락이었고 1건은 논쟁 여지 있는 assay FP (zlib1g/MiniZip)였습니다; 현재의 5건은 재분류하지 않았습니다 | assay 우세 |
| Rocky | 407건 일치, assay-only 2, grype-only 631 (rocky9) | assay-only 2건은 2026-08-28 기준 결함 있는 RLSA-2023:6699에서 기인 (peridot#204; 재검증하지 않음); grype-only 631건은 OS 타입 튜플이며, 2026-08-28 감사는 grype의 *fixable* 추가분 68건이 Rocky 대신 대입된 Red Hat 데이터이고 trivy는 이 중 0건을 확인함을 밝혔습니다 — 이 fixable 수치는 다시 도출하지 않았습니다 | assay 우세 (08-28) |
| Oracle | 143건 일치, assay-only 0, grype-only 84 (ol9) | grype-only 튜플은 FIPS 계열 ELSA의 메인라인 오매칭 — assay의 거부(D79)가 옳은 쪽 (2026-08-28 분류; 84건을 다시 나누지는 않음) | assay 우세 |
| Fedora | 82건 일치, assay-only 26, grype-only 32 (fedora) | 2026-08-28에 어드바이저리 수준 16/16, 한쪽에만 있는 CVE 튜플의 100%가 공유 어드바이저리 안; bare-advisory bridge가 그때 11건을 회수. 이번 실행은 어드바이저리 수준으로 다시 확인하지 않았습니다 | 양방향, 제한적 (08-28) |
| openSUSE Leap | 일치 0, assay-only 284, grype-only 0 (leap156) | grype v6에는 Leap 데이터 자체가 없음 (2026-08-28에 매칭 0건, 2026-10-12에도 다시 0건) | assay 단독 |
| SLES (bci-base) | 395건 일치, assay-only 8, grype-only 46 (bci156) | grype-only 튜플 46건 전부가 `go-module`입니다 — 이미지 안의 `/usr/bin/container-suseconnect` 바이너리에 컴파일된 Go 표준 라이브러리로, 이미지 스캔이 읽지 않는 부분입니다(D70 — 데이터 모델이 아니라 인벤토리); 2026-09-27 실행에서는 33건, 2026-10-12에는 46건. D117이 이제 이를 제한합니다: 이 타깃의 `maxGrypeOnlyApp.go-module`은 92이므로, 증가는 `ok`로 판정되지 않고 주간 실행에서 드러납니다. 2026-08-28의 데이터 모델 차이(fixable 한정 180/0/65: assay는 grype가 표현할 수 없는 no-fix 항목을 표현함; D91의 병합)는 다시 도출하지 않았습니다 | 데이터 모델 차이 + 인벤토리 공백 |
| Azure Linux 3.0 | 294건 일치, assay-only 31, grype-only 0 (azl3) | 감사의 유일한 진짜 assay 공백이었던 곳(2026-08-28 기준 일치 106, grype-only 140): Microsoft의 OSV export bot이 2026-03-10에 멈췄고 OSV.dev가 그 동결 스냅샷을 서빙해왔음. D106이 이 계열을 Microsoft의 일일 OVAL로 옮겼고, 이제 assay가 grype보다 31건 앞섭니다. trivy와의 277/277 일치는 2026-08-31에 측정한 값이며 다시 측정하지 않았습니다. 두 upstream 모두 통보 하루 만에 파이프라인을 고침 | **assay 우세** |
| RHEL (ubi8-nodejs) | 1319건 일치, assay-only 5008, grype-only 47 (ubi8n18) | 2026-08-28에는 assay 추가분의 98%가 `kernel-headers`였습니다 — Red Hat의 CSAF product tree가 커널 CVE에 대해 이 패키지를 명시하지만 grype는 해당 패키지를 전혀 내지 않고, trivy는 그때 assay 튜플 중 4,078건을 확인했습니다(둘 다 다시 측정하지 않았고, 추가분은 4531에서 5008로 늘었습니다). 반대 방향은 인벤토리 공백입니다: grype-only 튜플 47건 중 41건은 npm(2026-09-27에는 22건), 6건은 rpm이며 — npm은 `/usr/lib/node_modules/{npm,nodemon}/node_modules` 아래에 있어 이미지 스캔이 읽지 않는 부분(D70), SLES 행과 같은 공백입니다. D117이 이를 제한합니다: 이 타깃의 `maxGrypeOnlyApp.npm`은 82입니다 | OS 패키지는 assay 우세; npm은 인벤토리 공백 |
| RHEL 9 (ubi9) | 592건 일치, assay-only 3, grype-only 0 (ubi9) | 분류하지 않음; assay-only 3건은 살펴보지 않았습니다 | 거의 일치 |
| Debian 11 (지원 종료) | 211건 일치, assay-only 5, grype-only 0 (debian11) | D114가 지원 종료 타깃으로 차등에 추가; 5건은 분류하지 않았습니다 | assay 우세, 미분류 |
| Amazon Linux 2 (지원 종료) | 17 = 17, 전부 일치 (amazonlinux2) | D114가 추가 | 완전 일치 |
| Photon OS | 22 = 22 (photon4), 42 = 42 (photon5), 전부 일치 | 두 타깃 모두 한쪽에만 있는 튜플 없음 | 완전 일치 |
| Arch Linux | 9건 일치, assay-only 2, grype-only 0 (archlinux) | assay-only 2건은 분류하지 않았습니다 | assay 우세, 미분류 |
| Mariner 2.0 | 134건 일치, assay-only 53, grype-only 0 (mariner2) | 53건은 분류하지 않았습니다 | assay 우세, 미분류 |
| Bitnami (legacy postgresql) | 597건 일치, assay-only 6, grype-only 0 (bitnami-legacy-pg) | 이중 인벤토리(D99); 6건은 분류하지 않았습니다 | assay 우세, 미분류 |
| Hummingbird | 32건 일치, assay-only 7, grype-only 31 (hummingbird) | 양쪽 추가분 모두 분류하지 않았습니다 | 양방향, 미분류 |
| Alpaquita | 47건 일치, assay-only 0, grype-only 9 (alpaquita) | grype-only 9건 모두 grype의 CPE 폴백입니다(`nvd:cpe`에 대한 `cpe-match`, 뒤에 프로바이더 없음) — 2026-08-28 감사의 분류이며 2026-10-12 캡처에서 재확인했습니다 | 프로바이더 데이터 기준 완전 일치 |
| Liberica (BellSoft) | 61건 일치, assay-only 0, grype-only 29 (liberica21) | grype-only 29건 모두 Alpaquita와 마찬가지로 grype의 CPE 폴백입니다(2026-08-28 감사, 2026-10-12 재확인). 2026-10-12 실행은 이 타깃의 `maxFindings` ceiling(≤56, 실측 61)을 넘었습니다: 2026-10-04 이후 +26 튜플, BellSoft 피드의 `libcrypto3`·`libssl3`에 대한 2026년 OpenSSL CVE 13건이며, 제거된 것은 없고 61건 모두 grype도 보고합니다 — 무해한 upstream 성장이므로 재밴딩했습니다 | 프로바이더 데이터 기준 완전 일치 |
| CleanStart (postgres) | 일치 0, assay-only 0, grype-only 101 (cleanstart-postgres) | grype의 101건 중 100건은 `apk` 패키지에 대한 grype의 CPE 폴백입니다(2026-08-28 감사, 2026-10-12 재확인) — assay가 의도적으로 갖지 않는 매처입니다; CleanStart 자체 피드는 이 이미지에 대해 아무것도 보고하지 않으며, `minComponents` floor가 인벤토리가 실재함을 지킵니다. 101번째는 `go-module`(`/usr/bin/gosu`의 `github.com/moby/sys/user`)입니다: 이미지 스캔이 읽지 않는 이미지 내부 Go 바이너리(D70)이며, D117의 상한 2로 제한됩니다 | 프로바이더 데이터 기준 패리티; Go 바이너리 하나에 인벤토리 공백 |

요지: 차이의 대부분은 매처 버그가 아니라 **데이터 소스의 차이**였고, 이 작업이 찾아낸
진짜 버그 하나(D90 CSAF ID 충돌)는 수정됐습니다. 이 실측을 매주 반복하는 것이
D93입니다.

## 정책이 갈리는 곳

| 항목 | assay | grype | trivy | 맥락 |
|---|---|---|---|---|
| CPE/NVD 폴백 매처 | 없음 (의도) | 있음 | 벤더 어드바이저리 중심 | 차등에서 grype의 주요 false-positive 원천으로 분류 |
| FIPS/Ksplice/ESM 계열 | not evaluated로 보고 | 메인라인 데이터로 판정 | 구분 없음 | 맞는 데이터가 없으면 판정하지 않는다 (D53, D79) — 오라클 차등이 이 거부가 옳았음을 확인 |
| ignore 규칙 | 사유 필수 + 만료 경고 (D102) | 있음 | `.trivyignore` — CVE 나열, 사유 불요 | assay만 이유 없는 면제를 로드 단계에서 거부하고 억제를 모든 출력에 표시 |
| VEX 문서 입력 | OpenVEX 파일, `--vex` (D104) | 있음 | 4가지 방식 (repo·파일·OCI attestation·SBOM 참조) | 셋 다 OpenVEX 파일을 읽음; trivy는 repo/attestation 전달 방식을 추가로 갖춤. assay는 이유 없는 `not_affected`를 경고와 함께 건너뛰는 반면 grype는 조용히 받아들이고, 충돌하는 statement는 assay가 최신 우선으로, grype는 가장 이른 것으로 해소함 |
| 여러 소스의 등급 | 전부 보존, 최고치로 게이트 (D25) | 단일 표시 | 소스 우선순위로 하나 선택 | 19,715개 CVE 그룹 중 8,893개가 복수 레코드 — assay는 불일치 자체를 보여줌 |
| exit 코드 계약 | `2 > 1 > 0` 고정 (D11) | 유사하나 계약 명시 없음 | `--exit-code`로 사용자 지정 | assay는 "못 믿을 결과(2)"가 "발견(1)"보다 항상 우선 — CI가 고장과 clean을 혼동하지 못함 |
| 플래그 이름 | 의미가 같으면 grype와 동일 (D18) | — | 독자 체계 | 마이그레이션과 차등 스크립트를 위해 — 조용한 의미 차이는 금지 |

## assay에만 있는 것

| 항목 | 내용 |
|---|---|
| KISA/KNVD | 한국어 어드바이저리가 1급 소스; 한국어 산문 보강은 로컬 `assay db build`로 |
| 모든 소스의 등급 보존 | 두 DB가 한 CVE를 다르게 매기면 둘 다 보여주고 게이트는 최고치를 취함 (D25) — 리포트가 자기 판정과 어긋나지 않음 |
| 7개 게이트 + exit 계약 | `--fail-on`·`-unknown`·`-incomplete`·`-unfixable[=wont-fix]`·`-kev`·`-epss`·`-eol`, exit `2 > 1 > 0` (D11) |
| 불완전성의 원인 표시 | 평가 못 한 패키지는 개수+원인과 함께 skipped — clean 판정에 조용히 섞이지 않음; `--fail-on-incomplete=target`은 호출자가 고칠 수 있는 것만 게이트 (D36) |

## 출처

assay↔grype 실측과 패밀리별 분석은 [deferred-decisions.ko.md](deferred-decisions.ko.md)의
2026-08-24 차등 항목과 커버리지 재측정 항목에 있습니다. trivy 열은 2026-08-27에 읽은
[trivy.dev 문서](https://trivy.dev/latest/docs/coverage/os/) 기준입니다. 결정 ID는
[로드맵 스펙](superpowers/specs/2026-07-29-assay-roadmap.ko.md)을 가리킵니다.
