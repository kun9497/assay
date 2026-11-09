# 운영 범위 (operating envelope)

*[English](operating-envelope.md) · 한국어*

이 페이지는 자기가 만들지 않은 타깃 — 고객의 이미지 참조, 건네받은 체크아웃, 폼으로 업로드된
SBOM — 에 `assay scan`을 돌리는 서비스를 위한 것입니다. 스캐너가 스스로 한정하는 것, 링크된
레지스트리 라이브러리가 한정하는 것, 둘 다 한정하지 않아서 배포 측이 제공해야 하는 것, 그리고
각 항목을 검증하는 방법을 적습니다. 여기 적힌 모든 문장은 이 페이지를 쓴 커밋의 코드와 대조해
확인했고 근거가 되는 파일을 이름으로 적었습니다. 체크리스트의 명령은 그 코드에서 도출한 것이지
실행한 것은 아닙니다 — 서비스의 첫 S-2 리포트가 첫 실행입니다. `D` 번호는 그 동작을 정한 로드맵 결정입니다
(`docs/superpowers/specs/2026-07-29-assay-roadmap.md`). deferred-decisions의 "Safe handling of
externally supplied targets" 항목이 같은 경계의 설계 측 기록이고, 이 페이지는 그것의 운영 측
읽기입니다.

짧게 말하면: assay는 **무엇을 읽는가**(파일당 바이트, 스캔당 바이트, 링크 홉 수, config 크기)를
한정하고, 요청받으면 **이미지 스캔이 얼마나 오래 걸려도 되는가**를 한정합니다. **어디에
연결하는가**, **어떤 자격 증명을 찾아 쓰는가**, **프로세스가 메모리와 CPU를 얼마나 쓰는가**,
**강제 종료되면 무슨 일이 일어나는가**는 한정하지 않습니다. 이 넷은 배포 측의 몫입니다.

## 1. assay가 스스로 한정하는 것

아래 한도는 모두 닫히는 쪽으로 실패합니다: 부분 인벤토리로 계속 가지 않고, 스캔은 exit 2(CLI
계약의 "신뢰할 수 없음", D11)로 끝나며 리포트를 내지 않습니다. 숫자는 설정할 수 없습니다 —
배포마다 움직이는 한도는 버그 리포트에서 아무도 추론할 수 없는 숫자이기 때문이고(D112, "What
stays out"), 두 크기 한도가 패키지 수준 변수인 것은 테스트가 낮출 수 있게 하기 위해서일
뿐입니다(`internal/source/limits.go`).

| 한도 | 값 | 적용 범위 | 넘으면 | 결정 |
|---|---|---|---|---|
| 파일당 | **512 MiB** 압축 해제 기준 (`MaxFileBytes`) | 이미지 레이어에서 읽는 모든 파일(`Files`, `FilesUnder`, `FilesNamed`, `FilesMatching`); SBOM 타깃(`internal/scancmd/scancmd.go`의 `decodeSBOM`); jar 아카이브의 디스크 크기와 거기서 풀리는 각 엔트리(`internal/cataloger/jar/jar.go`) | exit 2: `<path> exceeds the 512 MiB per-file limit (D112)` | D112 |
| 스캔당 | **2 GiB** (`MaxScanBytes`) | 한 이미지의 모든 레이어 패스에 걸쳐 읽은 파일의 합; 별도로, jar 아카이브 하나가 중첩 아카이브까지 포함해 푸는 바이트의 합 | exit 2: `image reads exceeded the 2 GiB per-scan limit (D112) at <path>`; jar 는 `<archive> exceeds the 2 GiB per-archive decompression budget (D112) at <entry>` | D112 |
| 이미지 config | 선언 크기 **16 MiB** (`MaxConfigBytes`) | 매니페스트가 선언한 `config.size`, blob 을 요청하기 전에 검사 | exit 2: `image config is declared at <n> bytes, past the 16 MiB per-config limit (D112)`; blob 은 받지 않음 | D112 (QA 2026-11-02) |
| 링크 홉 | 원하는 경로당 **40** 링크(`maxSymlinks`, `internal/source/walk.go`) — Linux의 `MAXSYMLINKS`; 순환은 첫 반복에서 끝남 | 이미지 안에서 `/etc/os-release`와 패키지 데이터베이스를 찾아가며 만나는 심볼릭 링크와 하드링크 | 그 자체로 exit 2는 아님: 그 경로를 stderr 에 `not read: <path> (still a link after 40 symbolic links ...)`로, JSON `unread[]`와 SARIF `assay/not-read`로 보고하고 `--fail-on-incomplete`(두 범위 모두)를 트립함. 잃은 경로가 패키지 데이터베이스였으면 스캔이 아무것도 찾지 못하므로 exit 2가 됨 | D109, D130, 2026-10-22 감사 |
| 중첩 jar | **3** 단계 (`maxNestedDepth`, `internal/cataloger/jar/jar.go`) | jar 나 war 안의 아카이브 | 세 번째 단계를 넘는 아카이브는 집계되는 skip 이지 조용한 절단이 아님 | D70 |
| 디렉터리 깊이 | 루트 아래 **6** 단계 (`maxDepth`, `internal/cataloger/dirscan/walk.go`) | `dir:` 타깃 | 더 깊은 디렉터리는 가지치기되며, 의도적으로 공개하지 않음 — 오류 아님 | D26 |
| 시간 | **`--timeout <duration>`**, 기본은 꺼짐 | 레지스트리 fetch(`internal/source/image.go`의 `remote.WithContext`)와 레이어 walk — tar 엔트리마다 그 전에, 그리고 digest drain 의 32 KiB 청크 사이마다 컨텍스트를 확인(`readLayer`, `internal/source/layerdigest.go`의 `drainLayer`) | exit 2: `error: scan did not finish within <duration> (--timeout): <walk 가 있던 곳>` | D112 |

표가 함의하지만 래퍼가 평서문으로 읽어야 할 세 가지:

**`--timeout`이 없으면 데드라인이 없습니다.** `cmd/assay/main.go`는 스캔의 컨텍스트를
`context.Background()`로 만들고 플래그가 주어졌을 때만 데드라인을 붙입니다. 레지스트리
라이브러리의 기본 transport 는 dial 에 30초, TLS 핸드셰이크에 10초를 주고 그 뒤로는 아무것도
없습니다: 연결은 받아 주되 응답하지 않거나 레이어를 찔끔찔끔 보내는 레지스트리는 스캔을 무한히
붙잡아 둡니다(`internal/source/image.go`의 `Open` 위 주석이 그대로 그렇게 말합니다). 서비스는
모든 이미지 스캔에 `--timeout`을 주고, 그 값은 리포트의 `provenance.policy`에 기록됩니다(D120).

**`--timeout`은 이미지 스캔에만 닿습니다.** SBOM, 디렉터리, Go 바이너리, jar 타깃은 컨텍스트를
전혀 보지 않습니다(D112, "What stays out"): jar 예산은 그 리더의 작업을 직접 한정하고, `dir:`
타깃의 락파일은 `os.ReadFile`로 통째로 읽히며 크기 한도가 전혀 없습니다 — 운영자가 가리킨
디렉터리는 운영자의 것으로 취급됩니다. 고객 체크아웃을 스캔하는 서비스는 이 경로를 플래그가
아니라 6절의 프로세스 한도로 한정합니다.

**레이어 패스는 메모리가 아니라 시간을 곱합니다.** 모든 조회는 모든 레이어를 최신 것부터
한 바퀴 도는 full pass 이고(`internal/source/walk.go`의 `resolvePass`), 모든 패스는 diff id 를
검사하려고 각 레이어를 EOF 까지 읽습니다(D123). `Files`는 한 패스에 링크 홉마다 한 패스를
더하고(최대 41); distroless `status.d` 패스는 `/var/lib/dpkg/status`가 없을 때만, pacman 패스는
apk·dpkg·rpm 데이터베이스가 하나도 없을 때만 돌며, Bitnami 두 패스(`/opt/bitnami`에
`FilesMatching`, 이어 레거시 경로에 `Files`)는 모든 이미지에서 돕니다
(`internal/scancmd/scancmd.go`의 `catalogFromImage`와 `catalogBitnami`). 따라서 최소 Alpine
이미지도 full pass 네 번이 들고, 그래서 `--timeout`이 존재합니다: 크기 한도는 보관하는 양을
한정하지, 레이어를 몇 번 압축 해제하는지는 한정하지 않습니다.

## 2. 레지스트리 라이브러리가 한정하는 것

레지스트리 경로는 `github.com/google/go-containerregistry` **v0.21.7**(`go.mod`)이고,
`remote.WithContext`와 `remote.WithAuthFromKeychain`만 넘겨 호출하므로
(`internal/source/image.go`) 라이브러리 기본값이 그대로 적용됩니다. 아래는 모듈 캐시에서 읽은
그 버전의 사실입니다. 의존성 범프는 이 중 무엇이든 바꿀 수 있으니, 그런 범프의 리뷰어는 이
절을 다시 읽어야 합니다.

| 라이브러리 동작 | 값 | 출처 |
|---|---|---|
| 매니페스트·인덱스 본문 | **100 MiB** (`manifestLimit`) | `pkg/v1/remote/fetcher.go` |
| bearer 토큰 응답 본문 | **64 KiB** (`maxTokenBodySize`) | `pkg/v1/remote/transport/bearer.go` |
| 레지스트리 오류 본문 | **64 KiB** (`maxErrorBodySize`) | `pkg/v1/remote/transport/error.go` |
| 요청 재시도 | 총 **3회 시도**(`Steps: 3`), 첫 실패 뒤 약 1초, 두 번째 뒤 약 3초 대기(`Duration: 1s`, `Factor: 3`, `Jitter: 0.1`); 루프는 step 마다 요청을 한 번 보냄 | `pkg/v1/remote/options.go`(`defaultRetryBackoff`), `internal/retry/wait`(`ExponentialBackoff`) |
| 재시도 대상 | 일시적 네트워크 오류, `io.EOF`, `io.ErrUnexpectedEOF`, `EPIPE`, `ECONNRESET`, `net.ErrClosed`; HTTP 408, 429, 500, 502, 503, 504, 499, 522. 만료된 컨텍스트는 절대 재시도하지 않음 | `pkg/v1/remote/options.go`(`defaultRetryPredicate`, `defaultRetryStatusCodes`), `internal/retry/retry.go` |
| 다른 호스트의 **사설·루프백·링크로컬·미지정 IP 리터럴**로의 리다이렉트 | **거부**: `SSRF protection: redirect from "<host>" to private/link-local host "<ip>" denied` | `pkg/v1/remote/fetcher.go`의 `checkRedirectSSRF` |
| **DNS 이름**으로의 리다이렉트(무엇으로 풀리든) | **따라감** | 같은 함수: `net.ParseIP` 리터럴만 검사 |
| **같은 호스트**로의 리다이렉트 | 항상 **따라감** | 같은 함수, 첫 요청의 호스트(`via[0]`)와 비교 |
| foreign layer URL(매니페스트의 `urls[]`) | secure 레지스트리면 `https`여야 함; 사설·링크로컬 IP 리터럴 호스트는 거부 | `pkg/v1/remote/fetcher.go` |
| 프록시 | `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`를 `http.ProxyFromEnvironment`로 존중 | `pkg/v1/remote/options.go`의 `DefaultTransport` |
| 연결 | dial 30초, TLS 핸드셰이크 10초, 응답 헤더·본문 타임아웃 없음 | `pkg/v1/remote/options.go`의 `DefaultTransport` |

리다이렉트 규칙은 들리는 것보다 좁고, deferred-decisions 항목이 그것을 풀어 적습니다: 이
검사는 각 홉을 호출자가 이름 댄 호스트와 비교하고, IP 리터럴만 거부하며, 첫 요청은 아예 보지
않습니다. 자기 호스트명이 `169.254.169.254`로 풀리는 타깃이나, 거기로 풀리는
`metadata.internal.example`로의 리다이렉트는 fetch 됩니다. 그 틈을 6절의 egress 정책이 닫습니다.

요청 단위 재시도는 라이브러리의 것입니다. assay 가 자체로 더한 스트림 중간 재시도는 `db
update`와 `db build --seed`에만 있고(D140), 스캔의 레이어 읽기에는 없습니다. 스캔 중에
다운로드가 중간에 끊긴 레이어는 실패한 스캔(exit 2)이고, 래퍼가 스캔 전체를 다시 돌릴 수
있습니다.

## 3. 메모리 모델

스캔이 메모리에 무엇을 들고 있는지, 그리고 아직 아무도 재지 않은 것.

**버퍼링되고 한정됨.** 이미지에서 원하는 모든 파일은 파일당 한도 아래서 통째로 메모리에
읽히고(`internal/source/limits.go`의 `readEntry`), 한 스캔에 걸쳐 보관되는 파일은 스캔당
한도로 한정됩니다 — 그래서 이미지 스캔은 파일 내용을 최대 2 GiB 들고, 거기에
매니페스트(≤ 100 MiB, 라이브러리)와 config(≤ 16 MiB)가 더해집니다. 각 레이어의 나머지는
32 KiB 버퍼로 drain 되어 버려집니다(`drainLayer`); 시간이 들지 메모리는 들지 않습니다. SBOM 은
같은 512 MiB 읽기 한도 아래서 디코더로 스트리밍되며, 디코드된 구조체는 디코더의 것이고 문서
크기에 비례합니다. jar 는 엔트리당 최대 512 MiB, 아카이브당 2 GiB 를 풉니다. Go 바이너리는
`debug/buildinfo.ReadFile`(`internal/cataloger/gobinary/gobinary.go`)로 읽히는데, 파일 전체가
아니라 섹션을 읽습니다.

**버퍼링되고 한정되지 않음.** `dir:` 타깃의 락파일은 `os.ReadFile`로 통째로 읽히며
(`internal/cataloger/*lock*`, `requirements`, `gomod` 아래 모든 cataloger) 크기 검사가
없습니다 — 결정에 따른 것으로, 1절을 보세요. 적대적 체크아웃의 메모리는 cgroup 이 한정할
몫입니다.

**데이터베이스는 메모리 매핑됩니다.** 스캔은 스토어를 읽기 전용으로 열고
(`bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true})`, `internal/store/bolt.go`), bbolt 는
파일 전체를 매핑합니다. 조회가 건드리는 페이지가 페이지 인됩니다. 매핑은 파일 기반이라 cgroup
메모리에 집계되면서도 회수 가능합니다. 크기: 이 페이지를 위해 매니페스트를 읽었을 때 발행된
아티팩트의 데이터베이스 레이어는 **gzip 압축 기준 482,350,701 바이트**였고
(`ghcr.io/kun9497/assay-db:v9`, digest `sha256:ddd969bc…`, 2026-11-09). 발행된 데이터베이스의
압축 해제 크기는 이 페이지를 위해 재지 않았습니다. 유일한 로컬 수치는 2026-08의 부분 빌드가
Windows 디스크에서 3 GiB 라는 것인데, Windows 의 bbolt 는 파일을 mmap 크기까지 1 GiB 단위로
늘리므로(`bolt_windows.go`, `db.go`의 `mmapSize`, bbolt v1.5.0) 그 숫자는 측정값이 아니라 데이터의
상한입니다.

**피크 RSS 는 측정되지 않았습니다.** 이 페이지의 어떤 숫자도 측정된 상주 메모리 크기가 아니며,
위 한도에서 추론해서도 안 됩니다: 한도는 입력의 천장이지 프로세스의 천장이 아닙니다. 그
측정은 주간 스캐너 차분 러너(`.github/workflows/scanner-diff.yml`, `cmd/scandiff`)에 속합니다 —
이미 매주 고정된 이미지 26개를 스캔하므로 알려진 입력에 대한 타깃별 피크를 기록할 수 있는 한
곳입니다. 그것이 생기기 전까지 배포 측은 자기 타깃에 대한 자기 측정으로 메모리 한도를 정하고,
그 한도 아래서의 kill 은 5절이 설명하는 대로 읽습니다. Go 런타임의 `GOMEMLIMIT`은 가비지
컬렉터의 soft target 이지 상한이 아니며, 매핑된 데이터베이스를 한정하지 않습니다.

## 4. 자격 증명

레지스트리 스캔은 하나의 체인으로 자격 증명을 풀며, 먼저 답한 것이 이깁니다
(`internal/source/credentials.go`, D118):

1. **`ASSAY_REGISTRY_AUTH_USERNAME` + `ASSAY_REGISTRY_AUTH_PASSWORD`, 또는
   `ASSAY_REGISTRY_AUTH_TOKEN`** — `ASSAY_REGISTRY_AUTH_AUTHORITY`가 다른 레지스트리를
   지정하지 않는 한 타깃의 레지스트리에 범위가 묶입니다. 반쪽만 설정된 자격 증명은 레지스트리에
   닿기 전에 exit 2 이지(`internal/source/image.go`에서 호출되는 `newKeychain`), 조용히
   익명으로 떨어지지 않습니다.
2. **docker 로그인**(`authn.DefaultKeychain`): `~/.docker/config.json`이나
   `$DOCKER_CONFIG/config.json`이 있을 때만 참조합니다(`dockerConfigExists`). 홈 파일이 있어도
   라이브러리는 `$DOCKER_CONFIG`에서 로드하므로 **빈 디렉터리를 가리키는 잡별 `DOCKER_CONFIG`는
   `~/.docker`로 되돌아가지 않습니다** — 2026-10-13에 측정했고(D118) 7절의 격리 행이 검사하는
   성질입니다. `credHelpers`/`credsStore` 항목은 `PATH`의 `docker-credential-*`를 실행하며,
   config 를 읽는 것이 그것을 실행하는 데 대한 동의입니다.
3. **podman 로그인**: `$REGISTRY_AUTH_FILE`, 없으면 `$XDG_RUNTIME_DIR/containers/auth.json`을
   assay 가 직접 읽습니다. `XDG_RUNTIME_DIR`이 없으면 상대 경로가 아니라 경로 없음으로
   처리합니다(`podmanAuthPath`).

서비스가 관찰할 수 있는 것: 자격 증명이 제시됐을 때 stderr 한 줄이 출처만 이름 대고 그 밖엔
아무것도 내지 않습니다 — `registry credentials for <registry>: from the environment`(또는
`the docker config`, `the podman auth file`; `internal/scancmd/scancmd.go`의 `catalogImage`).
리포트의 `provenance.target.registryCredentials`가 같은 이름을 담습니다(D120). 401 이나 403 은
레지스트리와 제시했던 출처를 이름 대는 exit 2 입니다. **자격 증명 값은 stdout, stderr, 어떤
리포트에도 나타나지 않습니다.** 손으로 고친 config 의 한 바이트를 인용할 수 있는 라이브러리의
JSON 오류는 오프셋으로 줄입니다(`dockerConfigError`).

체인이 하지 않는 것: 테넌트를 격리하지 않습니다. 모든 출처는 프로세스의 환경과 사용자 홈에서
읽히므로, 한 호스트에서 돌리는 두 고객의 스캔은 잡마다 자기 `DOCKER_CONFIG`,
`REGISTRY_AUTH_FILE`/`XDG_RUNTIME_DIR`, `ASSAY_REGISTRY_AUTH_*`를 받지 않는 한 그 호스트
사용자가 가진 로그인을 공유합니다(D118, "What stays with the deployment"). SBOM,
`docker-archive:`, `oci-dir:` 스캔은 체인을 전혀 참조하지 않습니다.

## 5. 종료

**assay 는 시그널 핸들러를 설치하지 않습니다.** `cmd/`와 `internal/` 아래 어디에도 `os/signal`
사용이 없으므로 `SIGTERM`과 `SIGINT`는 Go 런타임의 기본 동작을 따릅니다: 프로세스가 즉시
종료됩니다. 지연된(defer) 것은 아무것도 실행되지 않습니다. 구체적으로:

- **exit-2 줄이 출력되지 않습니다.** 오류 경로에 도달한 적이 없기 때문입니다.
- **`--provenance` sidecar 가 쓰이지 않습니다.** sidecar 는 `Run`에서 defer 된
  `recorder.finish`가 쓰고(`internal/scancmd/scancmd.go`), `Run` 이전 실패는 `Refuse`가
  호출합니다(`internal/scancmd/provenance.go`) — "인자 파싱 이후 모든 exit 경로"(D120)는
  프로그램이 밟는 모든 경로를 뜻하고, kill 은 그중 하나가 아닙니다.
- kill 이 렌더링 도중에 떨어지면 **stdout 에 부분 리포트가 남을 수 있습니다.**

따라서 래퍼는 **sidecar 가 없는 것을 신뢰할 수 없는 결과**로, exit 2 와 같은 등급으로
다룹니다 — 그 반대는 끝나지 않은 스캔을 깨끗하다고 세는 것이므로, 이것이 유일하게 정직한
읽기입니다. sidecar 는 rename 이 아니라 `os.WriteFile` 한 번으로 쓰이므로, 파싱되지 않는
파일도 같은 식으로 읽습니다. `--timeout`이 협조적 대안입니다: 만료된 데드라인은 메시지를 가진
정상 exit 2 이고, sidecar 는 `exitCode: 2`와 오류 텍스트를 기록합니다. 래퍼 자신의 kill
데드라인보다 `--timeout`을 짧게 잡아, 스캔이 기록을 쓰는 경로로 끝나게 하세요.

## 6. 배포 측이 제공해야 하는 것

deferred-decisions 항목과 1–5절이 다루지 않는 것에서 나옵니다. 어느 것도 assay 가 결정할 수
있는 것이 아닙니다 — 각각 배포 측만 가진 "이 네트워크", "이 테넌트", "이 예산"의 개념이
필요합니다.

**Egress 정책.** assay 에는 호스트 허용 목록이 없고 주어진 것은 무엇이든 풀어 접속합니다. 유일한
거부는 2절의 라이브러리 IP-리터럴 리다이렉트 검사와 foreign-layer 검사입니다. RFC 1918 대역,
링크로컬(`169.254.0.0/16`, 클라우드 메타데이터 주소 포함), 루프백, 내부 DNS 존을 스캔 샌드박스의
네트워크 계층에서 막으세요. SBOM, `docker-archive:`, `oci-dir:` 스캔은 네트워크 호출을 전혀
하지 않으므로, 그것만 스캔하는 잡은 egress 를 전부 막고 돌릴 수 있습니다.

**테넌트별 자격 증명.** 잡 하나에 `DOCKER_CONFIG` 하나(테넌트에 없으면 빈 디렉터리),
`REGISTRY_AUTH_FILE` 하나, `ASSAY_REGISTRY_AUTH_*` 한 벌; 테넌트가 요청하지 않은 credential
helper 가 없는 `PATH`. stderr 의 출처 줄로 검증합니다(4절).

**프로세스 한도.** CPU, 메모리, pid 는 cgroup 으로(`docker run --memory --cpus --pids-limit`,
`systemd-run -p MemoryMax= -p CPUQuota= -p TasksMax=`, 또는 오케스트레이터의 대응물). assay 는
입력을 한정하지 프로세스를 한정하지 않습니다. 메모리 한도는 배포 측 자기 타깃에 대한
측정에서 나와야 하고(3절), 한도가 죽인 스캔은 5절대로 읽습니다.

**동시성 상한.** assay 안의 무엇도 동시에 도는 스캔 수를 제한하지 않고, 각 스캔은 3절의
버퍼를 최대로 들 수 있습니다. 데이터베이스 파일 하나는 읽기 전용 스캔 몇 개든 동시에 섬깁니다.
writer 락(D116)은 `db update`와 `db build`만 잡고, 스캔은 그것을 절대 기다리지 않습니다.

**디스크.** 스캔 경로는 시킨 것 외에는 아무것도 쓰지 않습니다 — stdout 으로 리포트,
`--provenance` sidecar. `internal/source`, `internal/scancmd`, `internal/cataloger` 아래에
`os.CreateTemp`도 `os.MkdirTemp`도 없습니다(임시 파일은 provider 들과 `db push`의 것입니다).
데이터베이스는 `$ASSAY_DB_DIR`, 없으면 사용자 캐시 디렉터리에 있고(`internal/store/store.go`의
`store.DefaultPath`), `db update`는 그 옆에 `<dbPath>.tmp`를 만들어 `<dbPath>.lock` 아래서
덮어쓰기 rename 하므로(D116) 데이터베이스 볼륨은 갱신 중 두 벌 분량이 필요합니다. 호스트당
또는 잡당 한 번 당겨 오고, 그 뒤는 읽기 전용으로 스캔하세요.

**작업 디렉터리.** `--config` 없이 스캔은 자기가 실행된 디렉터리에서 `.assay.yaml`을 발견해
그 waiver 를 적용하므로, 서비스가 만들지 않은 체크아웃이 자기 finding 을 waive 할 수 있습니다.
`--config none`을 주세요(provenance 에 `ignoreFile.path: "none"`으로 기록됩니다).

**exec 전 타깃 종류 검증.** 테넌트가 어떤 타깃 종류를 제출할 수 있는지는 배포 측이 정합니다;
assay 에는 그 플래그가 없습니다. `source.Classify`(`internal/source/classify.go`)는 스캔할
종류 — `TargetImage`, `TargetSBOM`, `TargetDirectory`, `TargetGoBinary`, `TargetJar` — 를
돌려주며, 맨 로컬 경로는 내용과 `os.Stat`으로 정하고, 이미지는 다시 레지스트리 참조,
`oci-dir:`, `docker-archive:`로 나뉩니다(`internal/source/image.go`의 `classify`). 레지스트리
참조만 받는 래퍼는 맨 경로와 두 로컬 이미지 스킴을 `exec` 전에 스스로 거부해야 합니다.

**명시적 `--platform`.** 기본값은 스캔하는 호스트의 플랫폼입니다(D119). 테넌트를 위해 스캔하는
서비스는 테넌트가 돌리는 플랫폼을 넘겨, 스캔된 이미지가 배포될 그 이미지이게 합니다. 리포트의
`image.match`가 exact·compatible·mismatch 중 무엇이었는지 말해 줍니다.

## 7. S-2 테스트 리포트용 체크리스트

통과 조건의 절마다 한 행입니다. 각 명령은 그 사실과 그 부재를 가르는 가장 작은 관찰입니다.
6절의 프로세스 한도를 건 채 스캔 샌드박스 안에서 돌리세요. 명령과 기대 관찰은 마지막 열이 이름을
댄 코드에서 도출한 것이고 이 페이지의 저자가 실행한 것은 아닙니다 — `timeout` 의 124 같은 종료
상태는 도구의 문서화된 값이지 관찰값이 아닙니다.

| 절 | 명령 | 기대 관찰 | 근거가 되는 사실 |
|---|---|---|---|
| 레지스트리 DNS 와 리다이렉트 | blob 요청에 한 번은 `http://169.254.169.254/latest/`로, 한 번은 `http://<10.0.0.5 로 풀리는 이름>/`로 `302`를 주는 테스트 레지스트리를 세우고, 각각에 `assay scan <registry>/img:tag --timeout 2m` | 첫째: exit 2, stderr 에 `SSRF protection: redirect from "<registry>" to private/link-local host "169.254.169.254" denied`. 둘째: 리다이렉트를 **따라감** — 네트워크가 막을 때만 스캔이 실패 | `checkRedirectSSRF`(go-containerregistry v0.21.7): IP 리터럴은 거부, DNS 이름은 따라감 |
| 사설 네트워크 | 샌드박스 egress 정책을 켠 채, 그다음 끈 채 `assay scan <10.x 또는 169.254.x 로 풀리는 이름>/img:tag --timeout 1m` | 켬: 타깃을 이름 대는 연결 오류로 exit 2; 받은 바이트 없음. 끔: assay 가 연결해 fetch 함 — 멈춘 것은 스캐너가 아니라 정책 | deferred-decisions, "Safe handling of externally supplied targets": assay 에 허용 목록 없음 |
| 자격 증명 격리 | 호스트 사용자로 `docker login <registry>`; 그다음 `DOCKER_CONFIG=$(mktemp -d) REGISTRY_AUTH_FILE=/nonexistent assay scan <registry>/private:tag 2>err.txt`; 그다음 `ASSAY_REGISTRY_AUTH_USERNAME/PASSWORD`를 설정하고 같은 명령; `grep -c "$PASSWORD" err.txt` | 첫 실행: exit 2, `UNAUTHORIZED`, `registry credentials for` 줄 없음(홈 로그인이 쓰이지 않음). 둘째: exit 0/1, stderr 에 `registry credentials for <registry>: from the environment`. 둘 다: grep 이 `0`을 출력 | D118; `internal/source/credentials.go`의 `dockerConfigExists`, `podmanAuthPath` |
| CPU/메모리/디스크/동시성 한도 | `docker run --memory=<M> --cpus=<C> --pids-limit=<P>` 아래서 `assay scan <image> --timeout 10m --provenance p$i.json` 을 `N`개 동시에; `strace -f -e trace=openat` 또는 `$TMPDIR`와 `$ASSAY_DB_DIR`의 전후 목록 비교 | 모든 실행이 `exitCode` 0, 1, 2 중 하나인 sidecar 로 끝남 — sidecar 가 없으면 한도가 죽인 것이고 `M`이 그 타깃의 피크보다 낮다는 뜻; stdout, sidecar, 데이터베이스 디렉터리 밖에 만들어진 파일 없음 | 3절(버퍼는 한정, RSS 는 미측정); 스캔 경로에 `CreateTemp`/`MkdirTemp` 없음; 읽기 전용 `bolt.Open` |
| 강제 종료 | `timeout -s TERM 5 assay scan <큰 이미지> --provenance p.json; echo $?; test -f p.json` | 셸 상태 124(맨으로 돌리면 143); stderr 에 `error:` 줄 **없음**; `p.json` 없음 | `cmd/`와 `internal/`에 `os/signal` 사용 없음; `recorder.finish`는 반환된 exit 에서만 실행 |
| 장시간 동작 | `assay scan <TCP 는 받되 응답하지 않는 레지스트리>/img:tag --timeout 10s --provenance p.json; echo $?`; 그다음 `--timeout` 없이 한 번 더, 벽시계를 두고 | 플래그 있음: ~10초 안에 exit 2, stderr 에 `error: scan did not finish within 10s (--timeout): …`, `"exitCode": 2`인 `p.json` 존재. 없음: dial 30초와 TLS 10초 예산이 지난 뒤에도 스캔이 계속 돌다가 래퍼가 죽일 때까지 감 | D112; `cmd/assay/main.go`의 `context.Background()` + `withScanTimeout`; `internal/source/image.go`의 `Open` 주석 |

표와 다른 관찰이 나온 행은 이 페이지에 대한 것이든 코드에 대한 것이든 finding 이고, 어느
쪽이든 `assay version` 줄과 함께 이슈로 가야 합니다 — 여기 적힌 사실은 그것을 읽은 커밋에 묶여
있습니다.
