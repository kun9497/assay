# 변경 이력

이 프로젝트의 주목할 만한 변경 사항은 모두 이 문서에 기록합니다. 형식은
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/)를 따르고, 프로젝트는
[Semantic Versioning](https://semver.org/)을 사용합니다. 항목에 따로 적혀 있지 않은 한 JSON 보고서의
`schemaVersion`은 바뀌지 않았습니다. 데이터베이스 저장소 스키마는 v0.1.0 이후 계속 9입니다.

## [Unreleased]

### Fixed
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

[Unreleased]: https://github.com/kun9497/assay/compare/v0.12.0...main
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
