# 게시 데이터베이스 아티팩트 서명과 pull 시 검증 — 설계 (D137)

*[English](2026-10-22-artifact-signing-design.md) · 한국어*

상태: 2026-10-22 승인된 설계. 구현 계획이 이 문서를 따른다. 결정 기록: 머지 뒤 로드맵 D137.
`docs/deferred-decisions.md` 의 보류 항목 "Signing and provenance for the published database artifact" 를
대체한다. 그 항목의 재검토 계기("제3자의 `db update` 가 이 레지스트리를 기본으로 신뢰하는 순간")는
2026-08-28 패키지 공개와 `dbcmd.DefaultRef` 의 신뢰로 이미 발화했다.

## 의도

`assay db update` 는 `ghcr.io/kun9497/assay-db:v<schema>` 를 받아 모든 스캔 판정이 기대는 데이터베이스로
설치한다. pull 은 digest 로 검증되지만 — 바이트가 manifest 와 일치한다 — 그 manifest 를 *누가* 게시했는지는
아무것도 말하지 않는다. 그 태그를 쓸 수 있는 누구든(훔친 `GITHUB_TOKEN`, 레지스트리 침해, 미러 운영자) 모든
고객의 스캐너가 "깨끗함"이라 말하게 만들 수 있다. 아티팩트는 프로젝트만 만들 수 있는 서명을 실어야 하고,
pull 은 그것이 없는 어떤 것도 설치를 거부해야 한다.

## 한 문단 결정

게시 워크플로가 push 된 아티팩트의 **digest** 에 프로젝트가 보유한 ECDSA P-256 키로 cosign CLI 의 키 기반
모드로 서명한다; 서명은 cosign 이 두는 자리, 같은 저장소의 `sha256-<digest>.sig` 태그에 산다. `db update` 와
`db build --seed` 는 이미 쓰는 `go-containerregistry` 경로로 그 태그를 받아, 바이너리에 내장된 공개키로 Go 표준
라이브러리만으로 서명을 검증하고, 서명된 payload 를 받은 digest 에 묶고, 어떤 실패에도 exit 2 한다. 새 의존성
없음. 릴리스 바이너리는 같은 키로 체크섬 파일에 서명하고 GitHub 의 빌드 provenance 를 덧붙인다.

## 왜 keyless 가 아니라 키 기반인가 (2026-10-22 둘 다 시제품으로 측정)

| | A: 키 기반, stdlib 검증 | B: keyless, `sigstore-go` |
|---|---|---|
| 추가 직접 모듈 | 0 | 2(`sigstore-go`, `protobuf-specs`); 간접 9 → 74, `go.sum` 30 → 384 줄 |
| 바이너리 | +34 KB | 7.2 MB → 20.0 MB |
| 검증기 | 143 줄 | 139 줄 + 레거시 `.sig` → bundle 변환 |
| 검증 시간 | 2 ms | 397 ms (TUF 갱신) |
| 검증 시 호스트 | 레지스트리만 | 레지스트리 + `tuf-repo-cdn.sigstore.dev` |
| 오프라인 | 오늘처럼 시끄러운 fetch 오류 | v1.3.0 에서 TUF 캐시도 `WithForceCache` 도 실패; 내장 신뢰 루트만 통과 |
| digest 묶음 | 검증기 자신의 검사 | 검증기 자신의 검사(라이브러리는 다른 이미지의 진짜 서명을 통과시킴) |
| identity | 키, 릴리스로 교체 | 워크플로의 SAN(`…/db-publish.yml@refs/heads/main`): 파일명·브랜치명·저장소 이전이 배포된 모든 바이너리를 깨뜨림 |
| 음성 사례(잘못된 키/identity, 변조, 서명 없음, 다른 서명, annotation 누락 / 네트워크 차단) | 5/5 거부 | 10/10 거부 |

둘 다 거부해야 할 것을 거부한다. B 는 372 모듈의 의존성 그래프, 2.8배 바이너리, 저장소 구조에 묶인 identity —
준비도 계획이 곧 바꿀 것(org namespace) — 를 비용으로 치른다. A 는 프로젝트가 이미 지니지 않은 것을 아무것도
치르지 않고, 하나뿐인 실제 부담 — secret 속 개인키 — 은 아래 교체로 답한다.

## 목표

1. 바이너리가 신뢰하는 키로 서명되지 않은 아티팩트는 절대 설치되지 않고 seed 로도 쓰이지 않는다: exit 2, *서명
   없음* 또는 *서명 불일치* 를 말하는 메시지, 절대 조용한 통과 없음.
2. 서명이 정확한 manifest digest 에 묶여, 다른 아티팩트로 옮긴 진짜 서명은 거부된다.
3. 새 직접 의존성 0; 스캔 경로는 손대지 않는다(레지스트리에 닿지 않는다).
4. flag day 없는 교체: 바이너리는 키 목록을 신뢰한다; 새 키는 무엇에든 서명하기 전에 릴리스에 들어가고, 옛 키는
   정해진 창 뒤에 나간다.
5. `db status` 와 스캔 provenance 가 설치된 데이터베이스를 무엇이 검증했는지 말한다.
6. 나이틀리의 어떤 것도 눈치채이지 않고 서명 없는 아티팩트를 push 할 수 없다.

## 비목표

- keyless/Sigstore identity, Rekor 투명성, *데이터베이스* 아티팩트의 SLSA. 릴리스 바이너리는 액션 하나에 코드
  없음이라 GitHub 빌드 provenance 를 받는다; 데이터베이스는 이번 라운드에서는 아니다.
- 스캔 리포트/attestation 서명(D120 의 기록). 같은 키, 나중 결정.
- 아티팩트 암호화. 공개다.
- 고객 쪽 신뢰 정책 파일. 신뢰 키는 바이너리의 것이다.

## 반목표 (동작하더라도 실패가 되는 것)

- 실수로 건너뛸 수 있는 검증: `.sig` 태그 없음을 "검증할 것 없음"으로 읽기, 태그를 떨어뜨린 미러가 조용히 통과,
  기본으로 켜진 플래그.
- 배포된 스캐너를 벽돌로 만드는 키 교체(릴리스까지 모든 `db update` 실패).
- 틀린 답이 숨을 만큼 큰 검증 코드. spike 의 143 줄이 예산이다.

## 제약

- 직접 의존성 다섯(CLAUDE.md); `CGO_ENABLED=0`.
- D14: 스캔은 절대 fetch 하지 않는다. 검증은 `db update` / `db build --seed` 에만 산다.
- D11/D16 모양: 신뢰할 수 없는 입력은 경계에서 exit 2, 절대 설치되지 않는다.
- D127: 아티팩트 기록은 `Meta` 안에, rename 전에 쓰인다; 무엇이 검증했는지도 거기 속한다.
- D60/D65 가드와 D114 게이트는 그대로; 서명은 `db push` 뒤, 그 밖이다.

## 설계

### 키

- 서명 identity 당 ECDSA P-256 키 쌍 하나, `cosign generate-key-pair` 로 생성. 개인키와 암호: GitHub 저장소
  secret `COSIGN_PRIVATE_KEY`, `COSIGN_PASSWORD`. 공개키: `internal/dbcmd/trust/keys/<id>.pub`(PEM, PKIX)로
  커밋하고 `go:embed` 로 내장.
- 키의 **id** 는 DER(PKIX) 바이트의 SHA-256 소문자 hex 앞 16자 — cosign 이 찍는 것이고 오류 메시지와
  `db status` 가 부르는 이름.
- 바이너리는 `trust/keys/` 아래 모든 키를 파일 순서로 신뢰한다. 하나면 충분; 교체 중에는 둘.
- 교체: (1) 새 공개키 커밋, 릴리스; (2) 그 릴리스가 나간 뒤 secret 을 바꿔 새 키로 서명; (3) 한 릴리스 뒤 옛
  공개키 삭제. 각 단계가 PR 이고 창은 최소 릴리스 하나. 침해된 키는 같은 순서를 압축한 것: 키를 제거하는 릴리스,
  그 다음 `workflow_dispatch` 로 현재 아티팩트를 새 키로 재서명.

### 서명 (워크플로)

- `db-publish.yml` 과 `db-backfill.yml` 의 `db push` 단계 뒤: `sigstore/cosign-installer` 를 **커밋 SHA 로
  고정**해 설치, `db push` 의 stdout 에서 push 된 digest 를 읽어(이미 `ghcr.io/kun9497/assay-db@sha256:…` 을
  찍는다) `cosign sign --key env://COSIGN_PRIVATE_KEY --tlog-upload=false --yes <ref>@sha256:<digest>` 실행.
  태그가 아니라 digest 로: `.sig` 태그는 digest 에서 유도되고, 태그 서명은 다음 push 와 경쟁한다.
  `--tlog-upload=false` 인 이유는 검증이 Rekor 를 보지 않고 Rekor 장애가 게시를 실패시켜선 안 되기 때문.
- 자기 검사 단계가 뒤따른다: `cosign verify --key <커밋된 .pub> --insecure-ignore-tlog <ref>@sha256:<digest>`
  가 exit 0 이어야 하고, 아니면 push 뒤에 잡이 시끄럽게 실패한다(아티팩트는 라이브이나 서명 없음; 아래 다음
  단계가 그것이 보이는 이유).
- `db push` 는 서명에 대해 아무것도 모른다. push 가드는 그대로.
- D28 스키마 bump bootstrap(손으로 도는 `db push`)은 README 런북에 "push, 그 다음 같은 두 명령으로 digest 에
  서명"으로 문서화; 잊은 bootstrap 은 새 태그에 대한 첫 `db update` 가 잡는다.

### 검증 (`internal/dbcmd`)

새 패키지 `internal/dbcmd/trust`(이름은 빌더 판단), 약 120 줄, stdlib + ggcr:

```
func Verify(ctx, repo name.Repository, digest v1.Hash, keys []PublicKey, opts ...remote.Option) (keyID string, err error)
```

1. pull 이 쓴 **같은** `remote` 옵션(인증, 컨텍스트; `/v2/` ping 을 반복하지 않도록 `remote.Reuse`)으로
   `sha256-<hex>.sig` 태그의 manifest 를 받는다. `MANIFEST_UNKNOWN` 은 *"<ref>@<digest> 의 아티팩트는 서명되지
   않았다"* 로 보고 — 전송 실패와 구별되는 오류.
2. 각 레이어를 순서대로: **64 KiB 상한**으로 레이어 바이트를 읽고(위협 모델에서 태그는 공격자가 쓸 수 있다),
   annotation `dev.cosignproject.cosign/signature`(base64 DER ECDSA)를 읽고, 신뢰 키마다
   `ecdsa.VerifyASN1(pub, sha256(rawPayload), sig)`. 어떤 키가 원시 바이트를 검증한 **뒤에만**: payload 를
   `json.Unmarshal` 하고 `critical.type == "cosign container image signature"` 와
   `critical.image["docker-manifest-digest"] == digest.String()` 을 요구.
3. 모든 검사를 통과한 첫 레이어가 수락하고 키 id 를 돌려준다. 아니면 오류가 모든 레이어의 사유를 나열한다(cosign
   은 재서명 때 레이어를 덧붙인다; 진단은 전부 이름 대야 한다).
4. payload 에서 다른 것은 읽지 않는다. `optional`, `docker-reference` 등은 무시 — 미러가 내주는 reference 는
   서명된 것과 설계상 다르다.

호출 지점:

- `Pull`(`db update`): `MetaOf` 의 스키마 검사 뒤(불일치는 여전히 요청 하나 비용), **`Unpack` 전**(서명 없는
  아티팩트는 임시 파일에 닿지 않는다). 오류 시: 메시지와 함께 exit 2; 설치된 데이터베이스는 그대로.
- `PullSeed`(`db build --seed`): 같은 호출, 같은 실패. seed 는 전체 이월(D66/D110)의 신뢰 입력이라 설치처럼
  검증돼야 한다.
- `--from <ref>`(고객 미러, D28): 정확히 같은 방식으로 검증. `.sig` 태그를 복사하지 않은 미러는 태그 이름을 대는
  *서명 없음* 메시지로 실패해 운영자가 복사할 수 있게 한다. 명시적 탈출구 하나: `db update` 의 `--allow-unsigned`
  는 경고를 찍고 설치하고 그 사실을 기록한다(다음 항목). `--from` 이 암시하는 일은 절대 없다.

기록, `db status`, provenance:

- `store.ArtifactRecord`(D127)에 `SignedBy string`(키 id) 또는 `Unverified bool` 추가. `db status` 가
  `signed:     key <id>` 또는 `signed:     NO (--allow-unsigned)` 를 찍는다. 스캔의 D120
  `provenance.database.artifact` 가 같은 두 필드를 실어, 리포트가 판정 뒤의 데이터베이스가 검증됐는지 말한다.
- 로컬에서 빌드한 데이터베이스는 둘 다 없다(pull 된 적 없음), 오늘처럼.

### 릴리스 바이너리

- `.goreleaser.yaml`: 같은 키로 체크섬 파일에 cosign `signs:`(`release.yml` 의 `COSIGN_PRIVATE_KEY`/
  `COSIGN_PASSWORD`); `…_checksums.txt.sig` 를 게시하고 README 에 키 기반 검증 안내.
- `release.yml`: 아카이브에 `actions/attest-build-provenance`(SHA 고정) — GitHub 네이티브 SLSA provenance,
  `id-token: write`, 코드 없음.
- `install.sh`: 2026-10-22 두 모양을 모두 만들어 공격해 본 뒤 정한 고정 스크립트 모양(아래).

### 설치기: 고정 스크립트, 키 내장 (확정)

두 모양을 같은 공격 행렬(정상 설치; 아카이브 변조; 릴리스 자산을 낡거나 없는 `.sig` 와 함께 일관되게 재작성;
저장소 트리 장악과 가져올 수 있는 모든 키 교체; `.sig` 없음; 호스트에 `cosign` 없음; 키 교체; `latest` 해석;
태그 가변성)로 시제품 시험했다. 둘을 가른 것:

- 태그의 저장소 트리에서 공개키를 가져오는 스크립트는 저장소 장악이 위조할 수 없는 것을 아무것도 검증하지 않는다:
  공격자가 자기 키로 재서명하고 가져올 키를 바꾸면 스크립트는 그들의 빌드 위에 "서명 검증됨"을 찍는다. 만들어진
  대로는 `.sig` 누락에 경고만 해서 — `.sig` 삭제가 공짜 다운그레이드였다.
- 키를 **내장**한 스크립트는 사용자가 돌리는 바이트가 진짜인 한 그 공격을 거부한다. 태그 URL 은 그것을 보장하지
  않는다: `git tag -f` 가 옮기고 `raw.githubusercontent.com` 은 5분 캐시 안에 옮겨진 태그를 다시 내준다. **커밋
  SHA URL 은 불변**이다.
- 시험 시점에 시험 머신에서 `api.github.com/repos/…/releases/latest` 가 rate limit(403, 60/h)에 걸려 있었고,
  `github.com/…/releases/latest` 의 302 리다이렉트는 인증 없이 태그를 풀었다. 오늘의 설치기는 그 한도 아래서
  실패한다.
- `openssl dgst -sha256 -verify <pub> -signature <der> <file>` 이 cosign 의 `sign-blob` 출력을 직접 검증한다
  (정상 OK; 변조 파일과 잘못된 키 실패). 설치기에 호스트의 `cosign` 이 필요 없다.

따라서:

1. README 한 줄은 **릴리스 커밋 SHA** 를 고정한다:
   `curl -sSfL https://raw.githubusercontent.com/kun9497/assay/<sha>/install.sh | sh`. 릴리스 잡이 릴리스를
   자르면서 그 줄(과 KO README)을 다시 쓰므로, 문서화된 줄은 항상 릴리스가 빌드된 커밋을 댄다. 태그는 산문에서
   편의로 적을 수 있어도 한 줄로는 절대 아니다.
2. 스크립트는 신뢰 공개키를 PEM heredoc 으로 내장하고 기본으로 **자기 버전**을 설치한다; 명시적 `<version>`
   인자는 다른 릴리스를 설치하되 여전히 내장 키로 검증한다. `latest` 조회도 `api.github.com` 호출도 없다.
   (`latest` 편의가 언젠가 필요하면 `/releases/latest` 의 `Location` 헤더를 읽지, API 는 절대 아니다.)
3. 아카이브, 체크섬 파일, `…_checksums.txt.sig` 를 내려받고, **openssl** 이 있으면 그것으로, 아니면
   `cosign verify-blob` 으로 서명을 검증하고, 둘 다 없으면 `ASSAY_ALLOW_UNSIGNED=1` 을 대는 메시지와 함께
   거부한다; 그 env 는 시끄러운 경고와 함께 오늘의 체크섬만 설치로 낮춘다. `.sig` 누락은 **거부**이지 경고가
   아니다: 첫 서명 릴리스부터 모든 릴리스가 그것을 첨부하고, `release.yml` 은 서명이 실패하면 없이 게시하는 대신
   단단히 실패한다.
4. sha256 검사는 서명 뒤에 무조건 남는다.
5. 교체: 릴리스 N+1 의 스크립트는 키 N 과 N+1 을 내장한다; N 에 고정된 스크립트는 N+1 릴리스를 그 릴리스와 함께
   게시된 설치기를 돌리라는 힌트와 함께 거부한다. 한 줄을 CI 에 복사한 사용자는 교체 때 SHA 를 올린다 — 스크립트와
   함께 다니는 신뢰 루트의 문서화된 비용.
6. Windows 는 스크립트 범위 밖이다(zip 은 게시되고, README 가 그것을 가리킨다).

### 롤아웃 순서 (flag day 위험)

게시 아티팩트가 서명되기 전에 검증하는 바이너리가 돌면 모든 pull 이 실패한다 — 그리고 워크플로 셋이 어떤
릴리스보다 먼저 `main` 에서 assay 를 빌드해 pull 한다: `db-publish.yml` 과 `db-backfill.yml` 은 `PullSeed` 로
seed 하고, `scanner-diff.yml` 은 `db update` 를 돈다. 그러므로 검증 **호출 지점**은 서명과 별도의 PR 이고, 빈
키 목록에 게이트되는 것은 아무것도 없다:

1. PR 1: `trust/keys/` 아래 공개키 커밋; `db-publish.yml`, `db-backfill.yml`, 새 `db-sign.yml` 이 push 뒤
   서명하고 자기 검사; 단위 테스트를 갖춘 `trust` 패키지; 기록 필드와 `db status` 줄. **`Pull`/`PullSeed` 의
   호출 지점은 아직 없음.**
2. 다음 나이틀리가 push 하고 서명한다. `:v<schema>` 에 `sha256-<digest>.sig` 가 있고 자기 검사가 통과했는지
   확인. 나이틀리가 멀면 현재 digest 로 `db-sign.yml` 을 띄워 3단계 전에 *현재* 태그가 서명되게 한다.
3. PR 2: `Pull` 과 `PullSeed` 의 호출 지점, 그 호출자 테스트, 변이 라운드. 머지부터 모든 워크플로 빌드가
   검증한다; 나이틀리 자신의 seed 단계가 첫 운영 검사다.
4. v0.12.0 릴리스. `main` 에서 빌드해 익명 pull 하는 주간 차분이 고객이 받는 아티팩트가 서명됐다는 상시
   end-to-end 검사다.

### 나이틀리 밖의 서명: `db-sign.yml`

입력 하나 `digest`(`sha256:…`)를 받는 `workflow_dispatch` 워크플로로, 저장소 secret 으로
`ghcr.io/kun9497/assay-db@<digest>` 에 서명하고 자기 검사를 돈다. 두 게시 워크플로 밖에서 서명이 만들어지는
유일한 길이며 런북 셋을 맡는다: D28 스키마 bump bootstrap(사람이 `:vN` 을 손으로 push 한 뒤 찍힌 digest 로
이것을 띄움 — 사람은 키를 절대 쥐지 않는다; 런북은 README 가 아니라 `docs/DESIGN.md` 의 bootstrap 절); 침해
대응(새 키 커밋·릴리스, secret 교체, 현재 digest 로 한 번 띄움); D110 복구 seed(아래).

### 서명 이전의 seed

`db build --seed` 는 `db update` 와 똑같이 검증하고 **탈출구가 없다**. 서명 이전 아티팩트 — digest 로 지정한
D110 복구 스냅샷, `PullSeed` 가 폴백하는 이전 스키마 태그, 미러의 사본 — 는 먼저 `db-sign.yml` 로 그 digest 에
서명해 쓸 수 있게 한다. 1분 걸리고 누구나 확인할 수 있는 서명을 남긴다. D110 복구 런북에 그 한 단계가 추가된다.
seed 는 전체 이월의 신뢰 루트다; 서명 없는 것을 들여보내는 플래그는 위의 반목표다. (`--allow-unsigned` 는
`db update` 전용으로 남고, 쓰이면 기록된다.)

### cosign 버전

spike 와 이 설계는 cosign 의 **레거시 서명 배치**(`sha256-<digest>.sig` 태그, simple-signing payload,
`dev.cosignproject.cosign/signature` annotation)를 쓰며, 이것은 cosign **v2.x** 의 기본이다. cosign
v3.0.0(2025-10-07)은 `sign` 의 기본을 OCI 1.1 referrer 로 저장되는 protobuf bundle 로 바꿨다 — `.sig` 태그에는
아무것도 놓이지 않고, 여기의 검증기는 모든 나이틀리를 서명 없음으로 보고하는데 v3 `cosign verify` 는 통과할
것이다. 그래서 설치기는 **v2.4 라인**에 고정하고(SHA 고정 `cosign-installer`, `cosign-release: v2.4.3`), 자기
검사는 같은 고정 바이너리로 `--key … --insecure-ignore-tlog` 를 돌려 Go 검증기가 읽는 같은 태그를 읽는다.
referrer/bundle 형식으로의 이동은 자기 검증기를 갖는 나중 결정이지 이것이 아니다.

## 검증 계획 (테스트)

- 프로세스 내 레지스트리: ggcr 의 `pkg/registry`(이미 모듈 그래프에 있음) over `httptest`. 서명은 cosign 의
  payload 모양으로 `crypto/ecdsa` 로 **테스트 안에서** 만든다; cosign CLI 는 테스트에 필요 없다. 옵트인 테스트
  하나(`ASSAY_COSIGN=path`)가 실제 CLI 로 서명해 형식 호환을 고정, 없으면 skip.
- 호출자 먼저(CLAUDE.md): 서명된 아티팩트에 대한 `Pull` 은 설치하고 키 id 를 기록; 서명 없는 것에는 임시 파일이
  생기기 *전에* exit 2; `Pull` 의 `Verify` 호출을 지우면 그 테스트가 빨강. `PullSeed` 도 같음.
- 표, 각 행 실행: 잘못된 키; 변조된 payload(올바른 digest 를 대는 재직렬화 JSON); `.sig` 태그 없음; 다른 digest
  의 진짜 서명; annotation 누락; 둘째만 유효한 두 레이어; 상한을 넘는 payload; 둘째만 서명하는 신뢰 키 둘;
  `--allow-unsigned` 는 기록과 함께 설치하고 없으면 같은 아티팩트가 거부.
- 끝났다고 하기 전에 돌릴 변이: 파싱 뒤 검증; digest 검사 제거; type 검사 제거; 상한 제거; 첫 레이어만;
  `MANIFEST_UNKNOWN` 을 성공으로; `--from` 이 `--allow-unsigned` 를 암시; 빈 키 목록이 수락.
- 워크플로: 자기 검사 단계가 서명 단계의 테스트; dry run 에서 일부러 틀린 키는 실패해야 한다.

## 인용할 측정치 (spike A, 2026-10-22)

0 모듈, +34,304 바이트, 143 줄, 2 ms, 서명에 레지스트리 요청 3(전송 재사용 시 2), 음성 5/5 거부, 오프라인 =
resolve 에서 `dial tcp … refused`, exit 2.

## 빌더에게 맡기는 것

- 패키지·플래그 이름; `SignedBy`/`Unverified` 를 한 필드로 할지 둘로 할지.
- 정확한 오류 문구, 단 *서명 없음*, *불일치*, *전송 실패* 는 세 개의 다른 문장이어야 한다.
- 미러(`--from`)와 `--allow-unsigned` 에 대한 README/integrations 문구.
- 워크플로가 받기 쉽도록 `db push` 가 digest 를 한 줄로 따로 찍을지(오늘은 `ref@digest` 를 찍는다;
  `--print-digest` 가 깔끔하면 그것도 좋다).

## 여기서 정리된 열린 질문

- *Rekor 가 죽으면?* 무관: `--tlog-upload=false`, 검증은 묻지 않는다.
- *에어갭 고객은?* 아티팩트와 `.sig` 태그를 미러하고(태그 둘, `crane copy --all-tags` 가 둘 다 복사) `--from`
  으로 pull; 검증은 그 미러에 대해 돈다. 태그를 실을 수 없는 미러를 위해 `--allow-unsigned` 가 있고 표식을
  남긴다.
- *secret 속 키가 GitHub 을 신뢰 루트로 만드는가?* 그렇다, push 하는 `GITHUB_TOKEN` 에 대해 이미 그렇듯. 얻는
  것은 토큰 탈취만으로는 더는 충분하지 않다는 것: 서명 키는 생명주기가 다른 둘째 secret 이고, 그 공개 반쪽은 모든
  고객의 바이너리에 고정돼 있다.
