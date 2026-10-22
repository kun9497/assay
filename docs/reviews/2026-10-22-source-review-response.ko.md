# 2026-10-22 소스 리뷰에 대한 응답

*[English](2026-10-22-source-review-response.md) · 한국어*

리뷰는 커밋 `0164c949d268453fbb2e1b0206a60117b7bf5015`(PR #178, D131 머지)을 검토해 조건부
정확성 결함 6건을 fixture, probe, 로그와 함께 보고했다. 이 문서는 각 건에 대해 확인 여부, 바꾼 것,
검증 방법, 결함 밖으로 미치는 영향, 남겨 둔 것을 기록한다 — 저장소만 갖고 다른 맥락이 없는 독자가
모든 단계를 다시 돌릴 수 있도록. 결정은 로드맵에 D132–D136 으로 기록했고, 이 문서는 작업의 기록이다.

기준: `main` 의 `0164c94` 가 리뷰 자신의 커밋이었으므로 그 사이 고쳐진 것은 없었다. 브랜치:
`fix/review-2026-10-22`. 커밋 순서: `d02e91f`(#6), `82bfd0d`(#1, #2, #3), `53d49aa`(#4),
`1fa7ef2`(#5), 테스트 보강 1건, 그 다음 문서.

## 1. 결함별 확인·해결 여부와 변경 파일

| # | 결함 | `0164c94` 에서 확인 | 해결 | 결정 | 운영 파일 |
|---|---|---|---|---|---|
| 1 | npm 별칭이 설치 이름으로 카탈로그됨 | 예 — 리뷰 테스트가 설명대로 실패: 별칭 exit 0, finding 0, Evaluated 1 | 예 | D132 | `internal/cataloger/npmlock/npmlock.go`, `internal/pkgmeta/package.go`(`Location.Install`), `internal/report/json.go`, `internal/matcher/matcher.go`(location key) |
| 2 | Ubuntu/RPM 표식이 다른 생태계 패키지를 skip | 예 — Go `+fips1`, `+esm1`, `-module+el9` 각각 skip, `--fail-on critical --fail-on-incomplete=target` 아래 exit 0 | 예 | D133 | `internal/matcher/matcher.go` |
| 3 | 이름이 같은 바이너리가 소스 버전을 무시 | 예 — `bsdutils` 는 1건 찾는데 `util-linux` 는 finding 0 / skip 0 / exit 0 | 예 | D134 | `internal/matcher/matcher.go` |
| 4 | 오래된 delta 가 더 새 아카이브 revision 을 폐기 | 예 — 요청 순서 `HEAD archive → GET changes.csv → GET doc → GET archive`; 낡은 delta 사본이 이김 | 예, 두 CSAF 프로바이더 모두 | D135 | `internal/provider/suse/{suse,delta,spool,csaf}.go`, `internal/provider/redhat/{redhat,delta,spool,csaf}.go` |
| 5 | NVD 점수 제거가 seed 된 rating 을 남김 | 예 — Rejected 와 Awaiting Analysis 모두 Annotate → bbolt → matcher 를 거쳐 CVSS 9.8 유지 | 예 | D136 | `internal/provider/provider.go`, `internal/provider/nvd/nvd.go`, `internal/store/{store,bolt}.go`, `internal/dbcmd/{dbcmd,push}.go`, `internal/dbartifact/dbartifact.go` |
| 6 | `--fail-on-epss=NaN` 이 게이트를 끔 | 예 — `0.5` exit 1; `NaN`, `nan` 은 finding 을 찍고 exit 0 | 예 | 버그 수정, 결정 없음 | `cmd/assay/main.go` |

검사 생략, 경고 숨김, 게이트 완화로 통과시킨 것은 없다. #5 는 게시 게이트에 허용치를 더하지만, 그것은
빌드가 스토어에 대해 측정한 수로 한정되고, 게이트는 여전히 출처가 통째로 사라지는 것을 거부한다.

## 2. 수정 전후의 재현과 실행한 검증

리뷰가 보낸 probe 는 전부 먼저 `go test -overlay` 로 `0164c94` 에 대해 그대로 다시 돌렸고, 6건 모두
재현됐다. *잘못된* 동작을 단언하던 probe 는 의도한 결과를 단언하도록 고쳐, 각각 옛 코드에서는 실패하고
새 코드에서는 통과하는 회귀 테스트가 됐다. 리뷰가 helper 만 찔러본 곳은 회귀 테스트가 실제 호출 경로를
몰고 finding·skip·exit code 를 읽는다.

| # | 수정 전 (probe 의 관찰) | 수정 후 (회귀 테스트의 단언) | 테스트 |
|---|---|---|---|
| 1 | `utility-alias: npm:lodash@4.17.20` 에 대해 npm 11.16.0 이 만든 lockfile 을 lodash 4.17.21 fix 로 `dir:` 스캔: exit 0, finding 0 | exit 1, finding 1, purl `pkg:npm/lodash@4.17.20`, Evaluated 1 — regular 엔트리, v3 별칭, v1 별칭 모두; 파서에서 scoped 별칭과 평범한 엔트리; 중첩 v1 별칭의 `Install` 은 실제 경로 | `internal/cataloger/npmlock`: `TestParse_V3AliasEntryIsNamedByItsRegistryIdentity`, `TestParse_V1AliasEntryIsNamedByItsRegistryIdentity`; `internal/scancmd`: `TestRun_NPMAliasIsMatchedAsTheRegistryPackage`; `internal/matcher`: `TestLocationKey_DistinguishesInstallPaths` |
| 2 | 깨끗한 sibling 옆의 Go `1.0.0+fips1` / `+esm1` / `-module+el9`: exit 0, finding 0, skip 1(`SkipCoverage`) | 각각 exit 1, finding 1, skip 0, Evaluated 2; Ubuntu `+esm1` 과 스트림 없는 Rocky `module+el9` 은 여전히 사유와 함께 skip | `internal/matcher/lineage_scope_test.go`(4건); `internal/scancmd`: `TestRun_LanguageVersionsWithDistroMarkersAreJudged` |
| 3 | dpkg status `Package: util-linux`, `Version: 1:2.38.1-5+deb12u3`, `Source: util-linux (2.38.1-5+deb12u2)`, fix `2.38.1-5+deb12u3`: exit 0, finding 0, skip 0 | `bsdutils` 와 `util-linux` 모두 exit 1, finding 1; matcher 에서 소스가 fix 에 있으면 깨끗하고 바이너리 이름 조회는 바이너리 버전 유지 | `internal/matcher`: `TestMatch_SameNameLookupComparesTheSourceVersion`, `TestMatch_BinaryNameLookupKeepsTheBinaryVersion`; `internal/scancmd`: `TestRun_DebianSameNameBinaryIsJudgedOnItsSourceVersion` |
| 4 | SUSE: HEAD t0, changes 행 t1 이 revision 1(fixed `9.6p1-1.0`)로 제공, 아카이브 GET t2 에 revision 2(fixed `9.6p1-1.1`): 레코드는 fixed `9.6p1-1.0`; 설치된 `9.6p1-1.0` 깨끗함 | 아카이브 GET 이 changes GET 보다 앞섬; t1 행은 fetch 되지 않음; 레코드는 fixed `9.6p1-1.1`; `DataAsOf` 는 t2. 행이 기준 시각 위에 있고 제공된 문서가 낡았을 때 아카이브 사본이 마지막에 방출되고 세어짐(`1 archive documents newer than the copy the delta fetched`). D129 대조군 유지(같은 날짜의 delta 사본이 대체, 1 superseded). 다운로드 도중 재생성은 0 바이트부터 재시작. Red Hat: 같은 네 가지 | `internal/provider/suse/snapshot_test.go`(3), `spool_test.go`: `TestFetch_ArchiveRegeneratedMidDownloadRestartsFromZero`; `internal/provider/redhat/snapshot_test.go`(3), `spool_test.go`: 같은 이름 |
| 5 | CVE 에 NVD 9.8 이 있는 스토어에 delta 페이지 `{"id": CVE, "vulnStatus": "Rejected"\|"Awaiting Analysis", "metrics": {}}`: rating 유지, finding critical, 체크포인트 전진 | 프로바이더에서: NVD rating 사라짐, 다른 기관 것은 유지, 같은 페이지의 rating 된 CVE 는 건드리지 않음, 진행줄 `1 returned without a score (rating withdrawn)`; `db build` 에서: NVD 키만 제거, rating 됐다 철회된 CVE 는 없어진 채 끝남, `Withdrawn` = 실제 있던 것의 제거 수, seed 의 `Withdrawn` 은 절대 이월되지 않음; 스토어에서: 정확한 키, 존재 여부 보고; `db push` 에서: 철회로 덮이는 감소는 통과, 그 이상은 거부, 0 은 거부 | `internal/provider/nvd/withdraw_test.go`(2); `internal/dbcmd/withdraw_test.go`(3, 게이트 표 포함); `internal/store`: `TestWithdrawRating_RemovesOneSourceAndReportsWhetherItExisted` |
| 6 | `--fail-on-epss=0.5` exit 1; `=NaN`, `=nan` 은 표에 finding 을 찍고 exit 0 | `NaN`, `nan`, `+Inf`, `-Inf`, `Infinity` 를 파싱에서 플래그와 값을 대며 거절; `run()` 을 통해: exit 2, stdout 비어 있음, stderr 가 플래그를 댐; `0` 과 `1` 은 유효 | `cmd/assay/main_test.go`(새 서브테스트 2), `cmd/assay/epss_nan_test.go` |

브랜치 head 에서의 검증: `gofmt -l cmd internal` 비어 있음; `go vet ./...` 깨끗함; `go test ./...`
통과(Windows amd64, Go 1.26.7, `CGO_ENABLED=0` 이라 `-race` 없이; CI 가 race detector 를 돈다).
리뷰 자신의 overlay probe 를 고친 트리에 그대로 돌리면 잘못된-동작 단언에서 실패하고 npm 것은 통과한다
— 기대한 반전이다.

변이 테스트, 한 번에 한 줄을 바꾸고 스위트를 오라클로, 각 커밋 뒤에:

| 범위 | 변이 | 결과 |
|---|---|---|
| #6 | 옛 범위 검사 복원; `math.IsNaN` 제거 | 1 잡힘, 1 **기록된 동치** — `!(v >= 0 && v <= 1)` 이 이미 NaN 을 거절; 명시적 `IsNaN` 은 독자를 위해 남김 |
| #2 | 각 생태계 게이트 제거 | 2 잡힘 |
| #3 | 옛 `lookupName != p.Name` 복원; 소스 버전 무조건 적용 | 2 잡힘 |
| #1 | v3 `name` 무시; `Install` 누락; v1 spec 무시; 첫 `@` 에서 자르기; location key 가 `Install` 무시 | 5 잡힘 |
| #4 | 항상 건너뛰기; 절대 안 건너뛰기; delta revision 0(SUSE, Red Hat); 재생성 검사 제거(둘 다); GET 을 무시하는 delta 기준 시각 | 8 잡힘 |
| #5 | 모든 철회를 셈; seed 의 수 유지(두 복사 경로); 게이트가 철회 무시; 게이트가 0 허용; 아티팩트 뷰 누락; NVD 가 절대 철회 안 함; `db build` 가 인터페이스 무시; 스토어가 항상 존재 보고; flush 없이 철회; 덮어쓰기 소실 | 11 잡힘 |

합계: 29 잡힘, 기록된 동치 1, 설명되지 않은 생존 0.

## 3. 기존 동작에 대한 영향과 남은 불확실성

**스캔 쪽(#1, #2, #3, #6) — 데이터베이스 변경 없음.** 다음 릴리스 바이너리는 정확히 위 네 모양에서만
다르게 판정하고 다른 곳에서는 그대로다:

- #1 은 별칭 npm 패키지가 매칭·보고되는 *이름* 을 바꾼다. JSON 리포트에 `locations[].install` 이
  생기고(비면 생략), `name` 으로 키를 잡던 소비자는 `utility-alias` 자리에서 `lodash` 를 본다. 디렉터리와
  패키지 이름이 다른 workspace 엔트리도 같은 식으로 영향을 받는데, 그것이 npm 의 `name` 필드를 올바로 읽은
  결과다. `name` 필드가 없는 엔트리는 바이트 단위로 전과 같다.
- #2 는 Ubuntu 아닌 생태계와 RPM 아닌 생태계에서 skip 두 가지를 없앤다. 언어 생태계에서 이 표식 때문에
  "not evaluated" 로 보고되던 패키지는 이제 판정되고, `--fail-on-incomplete` 의 개수도 그만큼 준다.
  Ubuntu, Oracle, RPM 동작은 그대로이며 대조 테스트가 붙든다.
- #3 은 바이너리와 소스가 이름을 공유하고 `Source:` 필드에 버전이 있는 dpkg 패키지의 비교 버전을 바꾼다.
  D41 을 몰았던 2026-08 fixture 로 측정하면 "name (version)" 형태는 이미지당 패키지의 1–15 % 이고, 그중
  이름이 같은 부분집합만 움직인다. 방향: 소스 namespace 가 아직 fix 에 못 미친다고 하는 패키지는 이제
  발견되고, fixed 라고 하는 것은 깨끗하다. 다른 카탈로거는 다른 소스 버전을 기록하지 않으므로 apk, rpm,
  pacman, SBOM 입력은 그대로다.
- #6 은 조용한 무동작을 exit 2 로 바꾼다. `NaN` 을 넘기던 파이프라인은 자기가 설정한 게이트 없이 돌고
  있었다.

**빌드 쪽(#4) — 데이터가 아니라 절차.** 게시된 아티팩트는 재빌드가 필요 없다: 나이틀리마다 아카이브를
다시 내려받고, 이 경쟁은 업스트림이 런 도중 아카이브를 재생성한 빌드에만 영향을 줄 수 있었다. 받아들인
비용: SUSE 의 사전 HEAD 가 사라짐(요청 하나 감소); 실패하는 delta 는 445 MB / 262 MB spool 뒤에 실패함;
진행줄에 카운터 하나 추가. 남은 불확실성은 `deferred-decisions.md`(알려진 함정)에 기록했다: tarball
조립 뒤 `Last-Modified` 전에 바뀐 문서는 다음 재생성 전까지 어디에도 없고(D129 자체의 하루이틀 지연),
더 새로우면서 비어 있는 아카이브 사본은 delta 의 레코드를 다음 빌드까지 남긴다 — 낡은 캐시를 통해서만
닿으며, `ArchiveNewerThanDelta` 가 0 이 아니면 신호다.

**빌드 쪽(#5) — 스키마 호환 메타데이터.** `store.Meta` 의 rating 출처 provenance 에 `withdrawn`(0 이면
생략)이, 아티팩트 쪽 `Meta` 에 `RatingWithdrawals`(데이터베이스에서 유도, annotation 으로는 절대 쓰지
않음)가 생긴다. 스키마 bump 없음: 옛 바이너리는 JSON 을 그대로 읽는다. 게시 게이트가 새로 받아들이는
것은 빌드 자신이 측정한 철회 수 이하의 감소뿐이며, 0 까지는 절대 아니다. 나이틀리가 보고하는 수
(`N returned without a score`)는 아직 분석 대기 중인 *새* CVE 가 대부분일 것이다 — 그 철회는 저장된
것을 찾지 못해 세어지지 않는다 — 그러므로 볼 숫자는 돌려받은 수가 아니라 저장 제거 수 줄이다.

**게시된 데이터베이스에서 측정하지 않은 것.** 리뷰의 fixture 는 각 결함을 입증하지 그 빈도를 입증하지
않는다. 별칭 npm 패키지, 소스 버전이 갈라진 같은-이름 dpkg 패키지, 철회된 NVD 점수가 실제 대상이나 라이브
아티팩트에 몇 건인지는 여기서 세지 않았다; 앞의 둘은 주간 스캐너 차분에 diff 로 드러나고, 셋째는 복구
런 자신의 줄로 드러난다(다음 절).

## 4. DB 재빌드 또는 기존 데이터 복구 필요 여부

- #1, #2, #3, #6: 없음. 바이너리가 바뀌고 아티팩트는 영향 없음.
- #4: 없음. 수정은 fetch 절차에 있고 다음 나이틀리부터 적용된다.
- #5: **운영 작업 하나가 남아 있다.** D136 이전에 NVD 가 철회한 rating 은 여전히 게시된 아티팩트에 있고,
  나이틀리 창은 수정되지 않은 CVE 를 다시 요청하지 않는다. `NVD_SINCE_DAYS=120` — API 최대 창이고 seed
  체인이 시작된 2026-08-14 보다 뒤로 닿는다 — 으로 빌드 한 번 하면 그 이후 수정된 모든 CVE 가 다시
  돌아와 낡은 것이 철회된다; `db push` 는 그 결과의 감소를 정확히 측정된 수만큼 허용한다. 절차는
  `docs/deferred-decisions.md` 에 기록했다. 그 런 전까지 게시된 아티팩트의 NVD rating 은 8월 이후
  reject 되거나 점수를 잃은 CVE 에 대해 리뷰가 말한 방향으로 낡아 있다(더는 critical 이 아닌 critical).
  몇 건인지는 모르며 그 런이 보고한다.

## 5. 해결한 것과 제안 단계인 것

브랜치의 코드로 해결: 결함 6건 전부, 위의 회귀 테스트·변이 증거·문서와 함께.

제안이며 미실행: `NVD_SINCE_DAYS=120` 복구 빌드(운영 작업, 누군가 지켜볼 수 있는 빌드로 미룸); 머지 뒤
첫 나이틀리의 `ArchiveNewerThanDelta` 와 `withdrawn` 줄 읽기; 그리고 #1–#3 이 실제 대상 몇 개를
움직이는지의 측정으로서 주간 차분의 다음 런.

## 이 리뷰의 단계를 다시 돌리기

저장소 루트에서, 브랜치 위에서:

```text
go test ./internal/cataloger/npmlock ./internal/matcher ./internal/scancmd ./cmd/assay -count=1
go test ./internal/provider/suse ./internal/provider/redhat -run 'Snapshot|ArchiveIsDownloaded|ArchiveCopyNewer|AsNewAs|Regenerated' -count=1 -v
go test ./internal/provider/nvd ./internal/dbcmd ./internal/store -run 'Withdraw|RatingCountRegression' -count=1 -v
go test ./... -count=1
```

옛 코드가 실패하는 것을 보려면 `0164c94` 를 체크아웃해 리뷰 문서가 설명한 대로 리뷰 자신의 overlay
probe 를 돌리면 되고, 새 테스트가 옛 코드에서 실패하는 것을 보려면 위 테스트 파일들을 `go test -overlay`
로 `0164c94` 에 대해 돌리면 된다.
