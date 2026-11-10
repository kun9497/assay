# 변경 이력

이 프로젝트의 주목할 만한 변경 사항은 모두 이 문서에 기록합니다. 형식은
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/)를 따르고, 프로젝트는
[Semantic Versioning](https://semver.org/)을 사용합니다. 항목에 따로 적혀 있지 않은 한 JSON 보고서의
`schemaVersion`은 바뀌지 않았습니다. 데이터베이스 저장소 스키마는 v0.1.0 이후 계속 9입니다.

## [Unreleased]

### Added
- **JSON `schemaVersion` 20**(추가형): `findings[].advisory.related`가 레코드 자체의 related 식별자를
  싣습니다 — Amazon ALAS, Fedora Bodhi, Oracle OVAL 레코드가 고치는 CVE를 적는 곳입니다. 전에는 JSON이
  그 CVE에 `ratings[].advisoryId`로만 닿았습니다. `cmd/truthset`도 `related`와 rating의 id로 라벨의
  CVE를 이어, Amazon Linux 2023 라벨의 거짓 미탐 네 건을 해결합니다. (D164)
- 프로브된 애플리케이션 패키지의 위치가 그 파일을 소유한 OS 패키지를 이름 붙입니다(D162):
  `findings[].package.locations[].ownedBy`는 그 경로를 파일 목록에 올린 rpm·deb·apk·pacman 패키지의
  `{name, version}`입니다 — rpm의 BASENAMES/DIRNAMES/DIRINDEXES 헤더 태그(세 데이터베이스 백엔드 모두),
  apk의 인라인 `F:`/`R:` 줄, dpkg의 `info/*.list`, pacman의 `files`. 뒤의 둘은 프로브의 기존 레이어
  패스에서 읽습니다(새 패스 없음). 그래서 ubi8/nodejs-18의 `npm`·`nodejs-nodemon` RPM이 번들한
  `usr/lib/node_modules` 아래 npm 트리와 Arch 패키지가 배포한 Go 바이너리는 그렇다고 말하고, 읽는
  사람은 배포판의 사본 — 그 권고는 OS 패키지의 것 — 과 이미지 작성자가 설치한 것을 구별할 수
  있습니다. 파일 단위의 정확한 소유와 레이어 순서를 봅니다: 자기를 이름 붙인 레코드보다 나중 레이어의
  파일(RPM 트리 위의 `npm install -g`)은 소유자 없음입니다. merged-`/usr` deb 목록의 `/bin/foo`는
  프로브의 `usr/bin/foo`를 소유합니다. 어느 OS 패키지도 올리지 않은 위치에는 `ownedBy`가 없고, 읽을
  수 없는 목록은 아무것도 소유하지 않으며 스캔을 실패시키지 않습니다. **JSON `schemaVersion` 19**
  (추가형).

### Changed
- 권고가 출시한 fix 이상인 빌드가 설치돼 있는데 권고의 열린 범위가 여전히 그 패키지를 affected로
  올려 두는 경우(SUSE의 "출시, In progress" 모양, Red Hat의 에라타 뒤 다시 열린 결함), finding의
  evidence는 "with no fixed version recorded" 대신 "`<v>` is at or above the released fix `<X>`; the
  advisory also lists the package as affected at every version, with no fix recorded for that"로 읽힙니다. 판정·
  `evidence.fixed`·fix 상태는 그대로이고 스키마 변경은 없습니다. (D163)
- `cmd/truthset`가 라벨의 `validFrom`을 데이터베이스에 대고 붙듭니다: 키의 `coverage[].dataAsOf`가
  `validFrom`보다 앞선 라벨은 판정하지 않은 것(`PREDATES`)으로 올리고, 보고서에는 세되 판정한 라벨
  수·지표·종료 코드에서는 뺍니다; coverage 날짜가 없는 스캔 문서는 전처럼 판정합니다. `validFrom`은
  `YYYY-MM-DD`여야 합니다(실재하는 날짜). 동결된 키(D110)는 동결일로 날짜를 매깁니다 — 둘 중 이른
  쪽; 모든 라벨이 데이터베이스보다 뒤인 실행은 빈 표를 통과시키지 않고 종료 2입니다. Debian:11 matcher
  라벨은 검증에 쓰인 키 동결일 2026-08-19를 `validFrom`으로 지닙니다. `truthset report` 문서는 **스키마
  2**(추가형: `predates`와 `PREDATES` 결과). (D161)
- `testdata/groundtruth/labels.json`이 라벨 84개에서 140개로, 패밀리 셋에서 아홉으로 늘었습니다: alpine,
  debian, leap에 rhel, alma, amzn, wolfi, npm, go가 합류했고, 새 라벨은 모두 업스트림 자체 권고에서
  조사해 다시 검증했습니다. `expect.fixed`는 제공자 레코드가 fix를 적는 대로 적습니다(Red Hat은 epoch
  포함, OSV Go는 `v` 없이). 로더는 Go purl의 이름을 모듈 경로 전체로, npm 스코프를 이름의 일부로
  읽습니다. 첫 라이브 실행: 126개 판정, 정밀도·재현율 1.000(0.937–1.000); amzn 라벨은 D113 개정 뒤
  처음 빌드되는 데이터베이스부터 판정됩니다. (D161)

## [0.16.0] - 2026-11-09

### Added
- `cmd/truthset`(D161): 커밋된 정답 집합에 대한 정밀도와 재현율. `testdata/groundtruth/labels.json`의
  라벨 — 어떤 버전의 패키지, CVE, 기대 판정, 그리고 읽어 온 업스트림 진술 — 하나하나를 SBOM 경로로
  당겨 온 데이터베이스에 대고 스캔해 판정합니다. 표는 패밀리별·전체 수치를 Wilson 95% 구간과 함께
  내고, 이어서 성립하지 않은 라벨을 전부 보입니다. `class: data` 행(알려진 데이터 공백)은 출력하되
  지표에서는 뺍니다. 종료 코드는 전부 성립 0, 라벨 하나라도 불성립 1, 스캔 불가 2. `-keep`, `-offline`,
  `-out`은 `cmd/scandiff`와 같습니다. 주간 `scanner-diff.yml`이 차분 비교 다음에 실행하고 1 또는 2면
  실패합니다. 2026-11-04 QA 하니스의 점검 84개로 시드했고, 첫 실행에서 라벨 하나를 SUSE 자체 진술로
  고쳤습니다(CVE-2026-34182의 출시 빌드는 여전히 "In progress"). `make build`로 배포하지 않으며
  보고서 스키마 변경은 없습니다.
- 이미지 스캔이 두 고정 위치에서 애플리케이션 패키지를 읽습니다(D160, D70 개정): `usr/lib/node_modules`,
  `usr/local/lib/node_modules`, `opt/app-root/src/node_modules` 아래의 설치된 `package.json`은 `npm`
  패키지가 되고(중첩 사본 포함, 각자 자기 경로에서; 버전 없는 것은 세어지는 skip), `usr/bin`,
  `usr/local/bin`, `bin`, `sbin`, `usr/sbin`, `usr/libexec`, `usr/local/sbin` 바로 아래의 Go 빌드
  정보를 가진 ELF 실행 파일은 `file:` 스캔이 도출하는 `Go` 패키지가 됩니다. 열 위치 전부에 레이어 패스
  하나 추가; ELF가 아닌 실행 파일은 4바이트 뒤 거절; D112의 한도는 그대로. 먼저 차등 타깃 26개 전부에서
  측정했습니다: 그 위치 밖에는 아무것도 없어 ubi8n18의 41건과 bci156의 47건 grype 전용 튜플이 이제
  assay의 판정 대상입니다. Python, Java, 그 밖의 위치의 npm 트리나 Go 바이너리는 읽지 않고 공개됩니다.
  바이너리의 버전 없는 `(devel)` main 모듈은 프로브에서 컴포넌트가 아니고(`file:` 스캔은 계속 셉니다,
  D36), 파일당 한도를 넘는 실행 파일은 읽어서 실패시키는 대신 헤더에서 거절하며, 새 레이어가 바이너리의
  경로에 둔 엔트리는 그것이 무엇이든 아래의 바이너리를 가립니다.

### Changed
- **JSON `schemaVersion` 18 — `inventoryScope.applicationPackages`로 분기하는 소비자에게 breaking**:
  그 필드에 네 번째 값 `partial`이 생기고(이제 모든 이미지 스캔이 이 값을 보고하며 `not-read`는 더 이상
  나오지 않음), `inventoryScope`에 `applicationScope[]`가 생깁니다 — ecosystem마다 `read`,
  `none`(프로브했으나 없음), `not-read`와 프로브가 읽는 `roots`. D141의 stderr 노트와 SARIF
  `assay/inventory-scope` 결과가 이제 무엇을 어디서 읽었고 무엇을 읽지 않았는지 말합니다. (D160)
- `cmd/scandiff`가 `npm`과 `go-module`을 인벤토리화된 타입으로 다루고(어느 쪽의 grype 전용 튜플이든
  floor가 판정, 어느 쪽에 대한 `maxGrypeOnlyApp` ceiling이든 거부), 그 타입이 지고 있던 D117 시드 셋을
  `.github/scanner-diff-targets.json`에서 제거했습니다. archlinux의 `maxFindings` 44 → 106,
  `maxAssayOnlyFixed` 25 → 84: captree의 Go 1.26.1 표준 라이브러리에 grype가 alpm 소유 바이너리에 대해
  보고하지 않는 CVE가 있습니다(브랜치 dispatch에서 53 / 42 측정, D93의 2배). (D160)
- `docs/operating-envelope.md`(와 한국어 쌍): 스캔이 스스로 한정하는 것(D112의 크기, 40 링크 상한,
  `--timeout`의 도달 범위와 그것 없이는 데드라인이 없다는 것), go-containerregistry v0.21.7이
  한정하는 것(manifest 100 MiB, 토큰 본문 64 KiB, 3회 시도, IP 리터럴로의 리다이렉트 거부와 DNS
  이름으로의 리다이렉트 추종, 프록시 환경 변수 준수), 피크 RSS를 미측정으로 표시한 메모리 모델, 자격
  증명 체인, kill 시 exit-2 줄도 `--provenance` sidecar도 남지 않는다는 것, 배포 측이 제공해야 하는
  것, 그리고 명령이 도출됐을 뿐 아직 실행되지 않은 S-2 테스트 리포트 체크리스트.
  `docs/integrations.md`와 `SECURITY.md`에서 링크. (QA 2026-11-04 S-2)
- deferred-decisions 항목 *LTS 이후의 Debian 11*이 QA 이미지 216건에 대한 두 번째 Debian 소스의
  2026-11-09 측정(Freexian ELTS 데이터: 사라질 것 0, ELTS 전용 수정 13, 사유 81, not-affected 오탐 7;
  Debian 자신의 tracker는 더 이상 bullseye를 싣지 않음)과 미루는 이유 — D110 carry 상호작용, 미상의
  약관, 비구독자에게 조치 가능한 이득 없음 — 를 기록합니다. (QA 2026-11-04 P-6)
- 표 각주, SARIF의 `assay/frozen-data`, `--explain`이 공유하는 동결 키 문장이 동결이 치르는 비용을
  말합니다: "…the upstream stopped publishing some or all of it, and fixes it has published
  since may be missing here"("may": 보이는 날짜는 동결 날짜라 데이터 자체의 날짜보다 앞설 수 있고,
  entry 수준 동결은 업스트림이 여전히 서비스하는 키 위에 있습니다). Debian LTS는 `Debian:11` 동결 뒤에도 bullseye
  DLA를 냈고 Freexian ELTS는 그 뒤 모든 bullseye 수정을 냈습니다. 날짜만 읽은 독자는 키를 완전한
  것으로 받아들였고, 옆의 EOL 줄 "still under ELTS until 2031"은 커버리지처럼 읽혔습니다.
  (QA 2026-11-04 P-6)
- `docs/integrations.md`에 "직접 만들지 않은 타깃에 assay 운영하기"가 생겼습니다: 서비스나 공용
  러너의 의무를 그것을 싣는 보고서 필드와 묶어 적었습니다(`--config none`, `summary.components`,
  `eol`, `coverage[]`, 그리고 현재 아티팩트에서 무엇을 거부하는지와 함께 `--db-max-age`). deferred
  항목 "외부에서 공급된 타깃의 안전한 처리"에 재검토를 기록했습니다. (QA 2026-11-04 P-5)
- 주간 스캐너 차등과 nightly D114 gate에 `ubi10` 타깃(`registry.access.redhat.com/ubi10/ubi`,
  digest 고정)을 추가했습니다. D93의 85% / 2배 규칙으로 측정 실행에서 심었습니다(minAgree 326,
  minFindings 333, maxFindings 784, maxAssayOnlyFixed 25). Red Hat의 2026-11-05 코퍼스 재생성이
  RHEL 10의 바이너리 no-fix 진술을 소스 패키지 id로 접었는데 RHEL 10 타깃이 없어 아무도 보지 못했습니다.
  스캔은 영향이 없었지만(전후 392건, `Package.Source`로 매칭) 다음 변화는 보이지 않았을 것입니다. trivy
  블록은 없습니다. trivy가 RHEL 10에 아무것도 보고하지 않습니다. (QA 2026-11-06)

### Fixed
- 키는 provider의 가장 오래된 아카이브가 아니라 자기 아카이브의 날짜로 찍힙니다. 스토어의
  `Provenance`에 `KeyAsOf`가 생겼고(additive Meta JSON, 스토어 스키마 bump 없음), OSV provider는
  키마다 그 키를 선언한 아카이브의 날짜를, Amazon provider는 릴리스마다 자기 활성 저장소 중 가장
  오래된 날짜를, carry-forward는 통째로 동결된 키에 동결 날짜를 기록하며, `--db-max-age`, D110의
  동결 날짜, 보고서의 `coverage[].dataAsOf`가 기록된 그 날짜를 읽습니다. 그 전에는 amazon provider의
  단일 `DataAsOf` — 2026-11-09 아티팩트에서 조용한 Amazon Linux 2 extras 토픽 하나가 정한
  2025-03-06 — 가 `--db-max-age=168h` 아래 모든 Amazon Linux
  2023 이미지 스캔을 거부하면서 도움이 될 수 없는 "run `assay db update`"를 처방했고,
  `Debian:11`의 동결은 Debian이 아니라 CleanStart 아카이브의 `Last-Modified`인 2026-08-19로
  찍혔습니다. 기존 동결은 그대로 carry되므로 `Debian:11`은 (더 오래된, 보수적인) 날짜를 유지하고,
  다음에 동결되는 키부터 자기 아카이브의 날짜로 찍힙니다. **JSON 보고서의 `schemaVersion`은 17**입니다
  (추가형, 새 필드 없음): `coverage[].dataAsOf`는 타입을 유지하지만 더는 항상 `db status`의 provider
  날짜와 같지 않습니다. 그 전에 빌드된 데이터베이스는 키별 날짜가 없어 다음 `db update`까지 이전처럼
  읽힙니다. 그 뒤 AL2023은 core, nvidia, kernel-livepatch 저장소 중 가장 오래된 날짜로 찍히므로 짧은
  게이트는 livepatch가 조용한 주에 여전히 거부할 수 있습니다. (D113 revised)
- Red Hat 리더가 진술(`known_affected` id, 또는 버전 없는 `fixed` id)에 대해
  `cpe:/o:redhat:rhel_els:N`(Extended Life-cycle Support)을 `Red Hat:N`으로 풉니다. Red Hat의
  2026-11-05 코퍼스 재생성이 RHEL 4~7의 모든 bare no-fix 진술이 매달리는 whole-product id를
  `enterprise_linux:N`에서 `rhel_els:N`으로 옮겼고, 2026-11-06 게시는 동결된 Red Hat:4~7 키에서
  (advisory, key) 쌍 4,085건과 no-fix 항목 460,000건을 잃었으며 살아 있는 키는 그대로였습니다. ELS 플랫폼 아래의 버전 있는 `fixed` id는 D47의 이유 — 채널의 fix는
  major에 키잉할 수 없다 — 로 계속 버리되, "non-mainline products"에 섞지 않고 따로 셉니다("fixed
  builds on an ELS channel"). 스캔의 Red Hat 안내는 EUS, AUS, TUS, E4S 옆에 ELS를 적습니다.
  (D47 개정; QA 2026-11-06)

## [0.15.0] - 2026-11-06

### Added
- `--config none` 은 ignore 파일을 전혀 쓰지 않고 스캔합니다. 작업 디렉터리에서 `.assay.yaml` 을 찾지
  않고 아무것도 waive 하지 않으며, 보고서의 provenance 에는 `ignoreFile.path: "none"` 이 기록됩니다.
  발견(discovery)은 스캔을 실행한 디렉터리를 읽으므로, 직접 작성하지 않은 checkout 을 스캔하면 그
  checkout 이 들고 있는 waiver 목록 아래서 실행됐고, 유일한 탈출구는 `ignore: []` 라고 적힌 파일이었습니다.
  (QA 2026-11-02 P3 #23)
- nightly publish 가 boolean `force` dispatch 입력을 받습니다. `true` 면 그 한 번의 실행에서 `db push`
  에 `--force` 를 넘겨, 사람이 거부를 실제 upstream 변화로 판정한 뒤 coverage 와 Ubuntu fix-state(D157)
  거부를 덮습니다. schedule 실행에는 입력이 없어 절대 force 하지 않고, D114 회귀 게이트는 어느 쪽이든
  돌고 거부합니다. 2026-11-03 과 11-04 nightly 가 Canonical 의 resolute 커널 SRU 로 `Ubuntu:26.04:LTS`
  에서 거부됐는데, 유일한 override 는 서명 키를 쥔 워크스테이션에서의 로컬 빌드였습니다.
  `internal/ciguard` 는 `--force` 를 그 입력의 조건문 뒤 한 자리에 붙들어 둡니다.
  (QA 2026-11-04 nightly 후속)

### Changed
- Red Hat 과 SUSE CSAF delta 패스는 변경 문서가 20,000 건을 넘더라도 아카이브가 21 일보다 오래됐을
  때에만 거부합니다. 더 신선한 아카이브 뒤에서는 건수와 아카이브 나이를 progress 줄에 적고 받아옵니다.
  Red Hat 이 2026-11-05 에 코퍼스 전체를 재생성했고(그날 20,514 건) 아카이브는 닷새 된 상태였는데,
  건수만으로는 그것을 멈춘 아카이브로 읽어 빌드를 실패시켰습니다. (QA 2026-11-06, D135 개정)
- 빈 `--config` 값(`--config=`, `--config ""`)은 parse 단계에서 `none` 을 안내하는 메시지와 함께 거부됩니다.
  전에는 조용히 "발견" 을 뜻했습니다. 그 자리에 비어 있는 변수를 넘기던 잡은 이제 작업 디렉터리의 `.assay.yaml`
  아래서 스캔하는 대신 exit 2 로 끝납니다. (QA 2026-11-02 P3 #23)

- 문서는 더 이상 exit `0` 을 "깨끗함" 이라고 부르지 않습니다. README, `docs/integrations.md`,
  `docs/compatibility.md`, `CONTRIBUTING.md` 는 이제 그것이 무엇인지 말합니다: 어떤 `--fail-on*`
  게이트도 걸리지 않았다는 뜻이며, 게이트 없이 실행한 스캔, finding 이 모두 waive 된 스캔, 컴포넌트가
  없는 SBOM 이 모두 이를 만족합니다; 무엇이 발견됐는지는 JSON `summary` 가 말합니다. 두 CI 예제는
  README 처럼 `main` 대신 최신 릴리스를 빌드한 커밋에서 `assay` 를 설치하고(릴리스 잡이 이제 넷을 함께
  고정하며, 넷 중 하나라도 브랜치나 태그를 가리키거나 서로 다르면 `internal/ciguard` 가 실패합니다),
  GitLab 예제는 `install.sh` 가 checksums 서명 검증에 쓰지만 `alpine` 이미지에 없는 `openssl` 을
  설치합니다 -- 그대로 복사하면 설치 스크립트가 설치를 거부했습니다. 한국어 사본도 함께 갱신했습니다.
  (QA 2026-11-04 #6, #8)

- `--db-max-age` 와 `--db-max-rating-age` 가 `=` 꼴뿐 아니라 `--timeout`, `--platform` 처럼 띄어 쓴
  꼴(`--db-max-age 48h`)도 받습니다. `docs/integrations.md` 와 D113 은 두 플래그를
  `--db-max-age <duration>` 으로 적는데, 그대로 베낀 그 표기가 바로 옆의 `=` 꼴은 되는 동안 exit 2 로
  끝났습니다(QA 2026-11-02 #12). 값 없이 끝에 홀로 선 플래그는 여전히 같은 메시지로 거부하고, 띄어 쓴
  꼴의 잘못된 값은 `=` 꼴과 같은 문구로 거부합니다.

- 문서와 도움말의 낡은 서술 여섯 곳(QA 2026-11-02 P3 #10, #13, #14, #15, #20): `--output sarif`
  도움말과 `docs/DESIGN.md`, `docs/deferred-decisions.md` 는 미평가 결과가 모두 note 수준이라고
  했지만, D109 와 D158 이후 읽지 못한 manifest 와 버전이나 purl 이 없는 컴포넌트는 warning 수준입니다;
  README 와 `CLAUDE.md` 는 `dirscan` 이 열세 가지를 읽는 lockfile 형식을 열 가지로 셌습니다; README 와
  `CLAUDE.md` 는 로드맵이 한참 지나친 끝 번호(`D146`, `D79`, `D36`)를 적고 있었고, 이제 끝 번호 없이
  번호 체계만 설명합니다; `docs/deferred-decisions.md` 의 서명 항목은 PR #181(D137 의 둘째 절반)이 검증을 이미
  내보낸 뒤에도 "검증은 둘째 PR 에서" 라고 했습니다; frozen 키 운영 절차는 `db-publish.yml` 의
  `workflow_dispatch` 가 입력을 하나도 선언하지 않는다고 했지만 #142 이후 D110 의 `seed` 입력을
  선언하고 있습니다(force 스위치는 여전히 없음). 한국어 사본도 함께 고쳤습니다.
- `scandiff` 의 표가 `GRYPE` 바로 뒤에 `A_BRIDGED` 와 `G_BRIDGED` 두 열을 새로 찍습니다. bare-advisory
  bridge 가 assay 쪽 집합과 grype 쪽 집합에 각각 더한 튜플 수입니다. 2026-10-13 wolfi 에서 `ASSAY` 가
  46 에서 74 로 오르는 동안 assay 자체 튜플은 45 에서 41 로 줄었는데, grype 데이터베이스가 자라면서 grype
  튜플 33 개가 assay 집합으로 bridge 된 것이었습니다. bridge 되는 target 의 `maxFindings` 위반이 비교 도구
  쪽의 성장일 수 있어 주간 리뷰가 그 분리를 손으로 세야 했습니다. floor 와 ceiling 의 의미는 바뀌지 않고,
  `ERROR` 행은 다른 카운터처럼 `0 0` 을 찍습니다. trivy 비교는 bridge 하지 않으므로 그대로입니다.

- DESCRIBES 관계가 실제 패키지를 지목하는 SPDX 문서가 더 이상 그 패키지를 잃지 않습니다. 파서는
  첫 DESCRIBES 대상을 그것이 문서 루트의 가짜 패키지인지 확인하지 않고 버렸으므로, 자기가 담은
  단 하나의 버전과 purl 이 있는 패키지를 기술하는 문서(프로젝트 자체의 `tiny.spdx.json` 포함)는
  "no components" 로 스캔되어 -- 카탈로그되지 않고, 세어지지 않고, 어느 skip 버킷에도 없이 --
  `--fail-on low --fail-on-incomplete` 아래 exit 0 이었고, DESCRIBES 가 둘이면 두 번째만
  살아남았습니다. 이제 DESCRIBES 대상은 어차피 패키지가 되지 않았을 때에만 제외되고(purl 없음,
  `pkg:oci`, 버전 없음 -- syft 와 Red Hat 이 루트에 쓰는 모양), 첫 번째만이 아니라 모든 DESCRIBES
  대상을 검사하며, 기술된 실제 패키지는 다른 패키지처럼 카탈로그되고 세어집니다(D84 개정).
  ubi9-micro 와 syft-1.51 의 루트 모양은 여전히 세지 않고 버립니다.
- 두 CSAF reader 모두 leaf purl 의 `epoch=N` qualifier 를 저장되는 fixed 버전에 `N:version-release`
  로 실어 나릅니다 -- rpmdb 카탈로거가 설치된 빌드를 쓰는 모양입니다. Red Hat 의 Hummingbird
  reader(D98)는 purl 의 `@version` 만 취하고 `?` 에서 멈췄으므로 nginx(epoch 2)와 tomcat10/11(epoch
  1)은 설치된 모든 빌드가 그 위로 정렬되는 epoch 없는 버전에서 fixed 로 저장됐고, 취약한 빌드가
  깨끗하다고 보고됐습니다 -- 최신 live 문서 160개의 Hummingbird purl 403종 중 67종, 주간 차등이
  스캔하는 바로 그 이미지에서입니다(QA 2026-11-02 #4, P1). Hummingbird reader 가 복사해 온 SUSE 의
  reader(D77)에도 같은 결함이 있었는데, 그 아카이브의 epoch qualifier 가 붙은 purl 은 전부 키 fold 가
  거절하는 Liberty Linux 빌드라 잠복해 있었습니다(#5, P3). 이제 둘 다 purl 을 `pkgmeta.ParsePURL` 과
  `pkgmeta.EVROf` 로 읽습니다 -- D83 이후 스캔 쪽이 SBOM purl 에 적용해 온 규칙입니다: 0 이거나 없는
  epoch 는 붙지 않고, 빈 버전에는 절대 붙지 않으며, 버전 없는 SUSE 빌드를 쪼개는 D131 은 그대로입니다.
  각 provider 의 진행 줄이 epoch 를 가진 fixed 항목을 셉니다(`HummingbirdFixedWithEpoch`,
  `RecommendedWithEpoch`). 발행된 아티팩트의 Hummingbird nginx/tomcat 레코드는 다음 야간 빌드가
  다시 만들 때까지 틀린 채입니다.
- SBOM 의 deb 와 rpm 패키지가 이미지의 것처럼 SOURCE 버전으로 판정됩니다. 두 리더 모두 purl 의
  `upstream` qualifier 에서 source 이름만 남기고 버전을 버렸습니다 -- deb 의
  `util-linux@2.38.1-5+deb12u2` 는 `@` 뒤 절반을 잃었고, rpm 의 `httpd-2.4.62-1.fc40.src.rpm` 은
  이름으로 벗겨졌습니다 -- 그래서 매처의 source 버전 비교(D41)가 SBOM 입력에서는 한 번도 돌지 않았고,
  바이너리 자신의 버전이 epoch 까지 포함해 source 키의 fix 와 비교되었습니다: util-linux
  `2.38.1-5+deb12u2` 에서 빌드된 bsdutils `1:2.38.1-5+deb12u3` 은 이미지의 dpkg status 에서는
  finding 이었고 같은 패키지의 CycloneDX 나 SPDX 에서는 skip 없이 깨끗했습니다(QA 2026-11-02 #1).
  deb 는 버전 절반을 유지하고, CycloneDX 리더는 purl 이 버전 없이 source 를 지목했을 때
  `syft:metadata:sourceVersion` 으로 채웁니다; rpm 은 SRPM 의 version-release 를 유지하고 그 epoch
  를 문서 전체에 대한 D153 의 규칙(main 패키지의 것, 없으면 형제들의 것)으로 놓으므로, httpd 옆의
  mod_ssl `1:2.4.62` 는 httpd 를 통해 발견되고 perl `4:5.32.1` 옆의 perl-B 는 걸리지 않습니다. deb
  source 버전에 대해 쓴 VEX 문장은 이제 그 source 에서 빌드된 SBOM 의 바이너리에 적용됩니다. 보고서의
  기존 `source.version` 필드가 채워지며, 스키마 변경은 없습니다.
- `db status` 가 `covers:` 범위를 출력할 때 Ubuntu LTS 와 SUSE 서비스 팩 릴리스를 읽습니다. 릴리스
  파서가 `.` 에서 자른 뒤 양쪽 모두 순수한 숫자를 요구했기 때문에 `Ubuntu:22.04:LTS` 와 `SLES:15.SP7`
  은 파싱 불가로 분류되어 파싱된 모든 릴리스 뒤로 정렬되었고, 실제 데이터베이스에서 이 줄은 Ubuntu
  14.04:LTS 부터 22.04:LTS 까지와 SLES 16.0/16.1 을 들고 있으면서도 `Ubuntu:23.10..26.04:LTS (11
  releases)` 와 `SLES:11..15.SP7 (21 releases)` 로 읽혀 -- Ubuntu 20.04 나 SLES 16 운영자에게 그
  릴리스가 범위 밖이라고 말했습니다 (QA 2026-11-02, #9). 이제 `:` 접미사는 숫자를 읽기 전에 떼어내고
  `SP` 는 minor 로 읽으므로, 같은 데이터베이스는 `Ubuntu:14.04:LTS..26.04:LTS (11 releases)` 와
  `SLES:11..16.1 (21 releases)` 를 출력합니다. 여전히 파싱되지 않는 형태(`edge`, `stream`,
  `rolling`)는 lexical fallback 을 유지하고, 한 숫자의 두 철자는 문자열로 정렬되어 양 끝이 정렬
  순서에 좌우되지 않습니다. `--output json` 은 키를 그대로 나열해 이미 맞았고, 개수는 처음부터
  바뀐 적이 없습니다.
- 어떤 comparer 도 읽지 못하는 설치 버전(dpkg 의 빈 Version, `(none)`, 잘못된 문자열)은 이제 열린 범위를
  포함한 모든 advisory 에 대해 target 원인으로 건너뜁니다. 전에는 `[0, )` 범위(Debian 의 미수정 집합, 모든
  CSAF no-fix 항목)가 비교 없이 sentinel 을 풀어 패키지를 AFFECTED 로 보고했고, 아무도 하지 않은 비교를 evidence
  가 적었으며, 바로 옆의 fixed 범위 advisory 는 올바르게 건너뛰어졌습니다(D9, D30). (QA 2026-11-02 #2)
- 닫는 경계만 있고 `introduced` 이벤트가 없는 범위는 잘못된 범위로 거부되어 건너뛴 목록에 들어갑니다. 전에는
  조용히 "영향 없음" 으로 걸어갔습니다. 현재 어떤 provider 도 이 꼴을 내지 않으며, OSV 스키마는 범위마다
  `introduced` 를 요구합니다. (QA 2026-11-02 #3)
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
- 야간 발행의 `seed` 입력은 스크립트 본문에 expression 으로 치환되는 대신 `env` 를 통해 빌드에 닿고,
  `ghcr.io/kun9497/assay-db@sha256:<64 hex>` 또는 `ghcr.io/kun9497/assay-db:<tag>` 꼴이 아니면 무엇이든
  빌드되기 전에 두 꼴을 들어 거부됩니다. 전에는 디스패처가 적은 값이 뒤 단계에서 서명 키를 쥐는 잡의 Build
  명령줄에 그대로 렌더링됐고(`db-sign.yml` 이 D137 부터 명시했고 `db-backfill.yml` 이 따르던 규칙), 입력
  설명은 "a ghcr digest" 를 요구해 맨 `sha256:<hex>` 도 만족했는데 go-containerregistry 는 그것을 Docker
  Hub 태그 `index.docker.io/library/sha256:<hex>` 로 해석하므로 그렇게 띄운 D110 복구는 한 시간 뒤에
  실패했습니다. `internal/ciguard` 는 이제 어떤 workflow 의 `run:` 블록에서도 입력을 읽는 expression 을
  거부합니다. (QA 2026-11-02 #16, #17)
- 발행·서명·backfill workflow 의 alert 잡은 성공하지 못한 status 잡 -- 실패했거나, 타임아웃이나 사람 손에
  취소된 -- 을 실패로 읽습니다. 전에는 `failure` 만 세어서, 감시 대상 잡이 통과하고 status 잡이
  GitHub 의 360분 취소까지 멈춰 있으면(`timeout-minutes` 가 없었음) `scripts/ops-alert.sh` 에 성공으로
  닿아 `status.json` 이 갱신되지 않았는데도 실패 이슈를 닫고 고정을 풀었습니다. 스크립트 자신의 머리말은
  취소를 실패라고 적고 있었습니다. 세 status 잡은 `timeout-minutes: 15` 를 갖고, `internal/ciguard` 가
  모든 alert 잡의 `RESULT` expression 과 모든 status 잡의 타임아웃을 요구합니다. (QA 2026-11-02 #19)

- 야간 발행은 `17 5 * * *`(05:17 UTC), 주간 scanner differential 은 `23 20 * * 0`(일요일 20:23 UTC)에
  예약됩니다. GitHub 의 큐가 가장 긴 minute 0 을 피한 것으로, 2026-10-13 부터 11-02 까지 `0 6 * * *` 의
  나이틀리 스무 번은 모두 4.2~7.6시간 늦게(10:12Z~13:38Z), `0 21 * * 0` 의 주간 실행은 2~3.5시간
  늦게(22:57Z~00:30Z) 시작해 월요일 리뷰 루틴에 50분 남짓의 여유만 남겼습니다. 여전히 늦는 실행이 예전
  자리에 떨어지도록 시를 앞당겼고, 예상 시작 구간은 `docs/DESIGN.md` 의 `status.json` 옆에 기록했으며,
  주간 workflow 의 주석은 더 이상 "Monday 06:00 KST" 라고 하지 않습니다. (QA 2026-11-02 #18)

### Security
- `github.com/klauspost/compress` 를 v1.20.2 로 올렸습니다. 2026-11-06 의 v0.15.0 릴리스 시도는 자체
  govulncheck 훅(`scripts/release-vulncheck.sh`)에 멈췄습니다. GO-2026-6865 (CVE-2026-116591,
  2026-11-05 공개)가 Red Hat CSAF 아카이브를 푸는 zstd 리더에서 (govulncheck 가 심볼 7 개를 들었고
  `fse.Decompress` 가 그중 하나) v1.20.2 이전 모든 버전에 닿아 있었고, 조작된 two-block 프레임이 디코더를 panic 시킵니다. 이전 릴리스
  어느 것도 이 수정을 담고 있지 않았고, 멈춘 시도에서 게시된 것은 없습니다.

### Fixed
- CycloneDX 문서의 subject 를 스캔합니다. 리더는 `bom.components` 만 걸었으므로
  `metadata.component` -- 명세가 SBOM 의 대상, 즉 라이브러리 자체의 SBOM 이라면 그 라이브러리를
  두라고 정한 자리 -- 에 적힌 패키지나 그 아래 중첩된 패키지는 카탈로그되지 않았습니다: 스캔되지
  않고, 세어지지 않고, 어느 skip 버킷에도 없이. 거기에 쓴 lodash 4.17.20 은 공개 데이터베이스에 대해
  `--fail-on low --fail-on-incomplete=target` 아래 component 0, finding 0, exit 0 으로 스캔됐고, 같은
  패키지를 `bom.components` 에 두면 CVE-2021-23337 을 포함한 finding 5건이었습니다. 이제 subject 는
  `bom.components` 다음에, SPDX 의 DESCRIBES 가 따르는 규칙으로 카탈로그됩니다: 루트 모양 -- purl
  없음(syft 의 container), `pkg:oci`, 버전 없는 purl -- 은 전처럼 세지 않고, 그 밖에는 후보 또는
  집계된 skip 이 되며, subject 아래 중첩된 components 는 최상위처럼 걷습니다. subject(또는 그 아래)와
  `bom.components` 양쪽에 적힌 패키지는 둘이 아니라 패키지 하나, finding 하나입니다: 동일성은
  type·name·version·ecosystem 키이므로 한정자만 다른 purl 은 패키지 하나, 버전 없는 purl 이 component
  버전 둘에 걸치면 패키지 둘이고, 버린 쪽 항목의 location 과 source 식별자는 보고되는 쪽에 남깁니다.
  중복 제거는 subject 트리 대 `bom.components` 뿐입니다 -- 최상위에 두 번 적힌 것도, subject 아래에
  둘 다 중첩된 것도 둘로 남습니다. subject 이거나 그 아래인 배포판 패키지는 최상위 쌍둥이처럼 문서의
  operating-system component 로 키를 잡습니다. (QA 2026-11-02 "CycloneDX subject", 2026-11-04 재현;
  PR #238 리뷰)
- 표(table) 보고서를 쓸 수 없으면 exit 2 입니다. stdout 이 닫혔거나, 가득 찼거나, 읽기 전용으로
  열린 경우 `--output json` 과 `--output sarif` 는 이미 `error: write report` 와 함께 exit 2 였고,
  나열할 finding 이 있는 표도 그랬습니다. 그러나 나열할 것이 없는 표 -- 깨끗한 스캔, 빈 문서,
  모든 finding 이 waive 된 스캔 -- 는 아무것도 쓰지 않고 exit 0 으로 끝났으며 `reportSha256` 도
  남기지 않았으므로, 기본 출력을 쓸 수 없는 파일로 리다이렉트한 잡은 도착하지 않은 보고서를
  통과로 읽었습니다. 이제 표가 쓰는 모든 줄을 검사하고, 첫 실패를 다른 렌더러와 같은 방식으로
  stderr 에 보고합니다. 릴리스 바이너리로 main 에서 재현했고, 수정은 `scancmd.Run` 과 CLI 진입점
  양쪽에서 테스트로 붙잡습니다. (QA 2026-11-04, 차원 4 #5; QA 2026-11-02 에서 처음 발견)
- `assay scan --help`, `assay scan -h`, `assay db --help`, `assay db -h`, `assay db help` 는
  `assay help` 처럼 usage 를 stdout 에 출력하고 exit 0 입니다. 전에는 `error: unknown flag` /
  `error: unknown db subcommand` 로 exit 2 였고 stdout 에는 아무것도 없었습니다. `db` 는 데이터베이스를
  찾기 전에 help 에 답하므로, 사용자 캐시 디렉터리가 없는 머신(임시 CI 컨테이너, 숫자 uid 와 HOME 없이
  실행한 `docker run`)에서도 `error: locate database` 대신 usage 를 받습니다 -- `scan --help` 는
  거기서 이미 그렇게 답하고 있었습니다. (QA 2026-11-04 #7)
- Ubuntu 26.10 finding 이 Canonical 의 fix state 를 갖게 됩니다. tracker 의 `stonking` 코드명이
  `db build` 가 tracker 행을 해석하는 표에 없어서 모든 `stonking_<pkg>` 행이 unknown-codename
  tuple 로 버려졌고, 2026-11-01 에 게시된 artifact 는 `Ubuntu:26.10` 에 fix 없는 range 16,289 개를
  들고 있으면서 wont-fix/not-fixed state 는 0 개였습니다(`dev.assay.ubuntu-fix-states`). D157 의
  publish guard 는 0 으로 게시된 키를 볼 수 없습니다. 이제 `resolute` 가 `26.04` 로 가듯 `stonking` 은
  `26.10` 으로 갑니다. `tenacious`(27.04, 개발 릴리스)와 `devel` 은 의도적으로 매핑하지 않습니다.
  (QA 2026-11-04)
- jar 의 엔트리는 하나씩만이 아니라 합계로도 상한을 받습니다. cataloger 는 각 엔트리의 압축 해제
  바이트를 512 MiB 파일당 한도로 막았지만 그 합계는 아무것도 막지 않았으므로, deflate 된 64 MiB
  엔트리 열두 개를 담은 784 KB jar 가 768 MiB 를 풀어냈고, 같은 모양을 아카이브 한도까지 키우면 수백
  GiB 에 이릅니다. 이제 `jar.Parse` 한 번에는 모든 엔트리와 모든 중첩 아카이브에 걸쳐 2 GiB 의
  예산 -- D112 의 스캔당 수치, `source.MaxScanBytes` -- 이 있고, 각 읽기가 풀어낸 만큼 차감됩니다.
  예산이 바닥나면 아카이브, 예산, 바닥난 엔트리를 이름으로 대는 오류이며 아카이브에서 아무것도
  돌려주지 않습니다. `jar:` 타깃에서는 exit 2 이고, `dir:` 스캔 안의 jar 에서는 크기 초과 아카이브가
  이미 받는 집계된 failed skip -- JSON `unread[]`, 표의 개수, `--fail-on-incomplete=target` --
  이며, 아카이브의 것인 양 제시되는 부분 인벤토리는 결코 아닙니다. (QA 2026-11-02 #22)
- 레지스트리 경로에서 이미지 config 는 가져오기 전에 선언된 크기로 거부됩니다. 라이브러리는 config
  blob 을 통째로 읽고 그 읽기를 manifest 가 선언한 크기 -- 레지스트리 자신의 말 -- 로만 제한하는데,
  256 MiB config 를 선언한 manifest 는 digest 불일치가 드러나기 전에 256 MiB 를 스트리밍하고 그 두
  배를 할당했습니다. config 가 처음 필요한 시점에 manifest 는 이미 손에 있으므로, 모든 config 읽기
  -- 단일 이미지의 platform 확인, descriptor 가 platform 을 대지 않는 index 항목의 platform, 모든
  이미지 경로가 검증하는 diff id -- 가 이제 16 MiB(`source.MaxConfigBytes`, 상수: 실제 config 는
  킬로바이트 단위) 를 넘는 선언 크기를 선언 크기와 한도를 이름으로 대는 오류로 거부하고, blob 은
  요청되지 않습니다. (QA 2026-11-02 #24)
- `scandiff` 는 `name` 이 평범한 파일 이름이 아닌 타깃 -- `.`, `..`, `/` 나 `\` 가 든 것,
  `filepath.Base` 가 줄일 모든 것 -- 을 floors 파일을 읽을 때 항목을 지목하며 거부합니다. 이름은
  `-capture` 경로에 join 되므로 `"name": "../../x"` 는 capture 디렉터리 밖에 capture 를 썼습니다.
  (QA 2026-11-02 #25)
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

[Unreleased]: https://github.com/kun9497/assay/compare/v0.15.0...main
[0.15.0]: https://github.com/kun9497/assay/compare/v0.14.0...v0.15.0
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
