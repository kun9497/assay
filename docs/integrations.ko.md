# CI 통합

*[English](integrations.md) · 한국어*

`assay scan`은 게이트로 삼도록 설계됐습니다: 결과는 stdout, 진단은 stderr로 나가고, 종료
코드가 계약입니다 — `0` 깨끗함, `1` 임계 이상의 finding, `2` 실행 불가 또는 신뢰 불가,
우선순위는 `2` > `1` > `0`. 파이프라인에 필요한 건 이게 전부입니다.

바로 복사해 쓸 수 있는 완전한 예제 두 개:

- **[GitHub Actions](ci/github-actions.yml)** — push 시 스캔, findings를 Security 탭에
  기록(SARIF), high 이상이면 빌드 실패.
- **[GitLab CI](ci/gitlab-ci.yml)** — 잡에서 스캔, 리포트를 아티팩트로 보관, 종료 코드로
  파이프라인 실패 판정.

## 한 줄 패턴

```bash
assay scan <target> --fail-on high        # high 이상이면 exit 1, 신뢰 불가면 exit 2
```

`<target>`은 레지스트리 이미지, `docker-archive:`/`oci-dir:` 경로, SBOM, 바이너리,
디렉터리입니다. `--output sarif`(또는 `json`)를 붙이면 기계가 읽는 리포트를 stdout으로
내보내니 파일로 리다이렉트하세요. `--fail-on` 외에 `--fail-on-kev`, `--fail-on-epss <n>`,
`--fail-on-eol`, `--fail-on-unfixable[=wont-fix]`도 있으며, 게이트할 만큼 조합하면 됩니다.

## findings 기록 먼저, 게이트는 그다음 — 순서가 중요

GitHub 예제는 스캔을 한 번 돌려 SARIF를 파일로 쓴 뒤, 종료 코드로 빌드를 실패시키기
**전에** `if: always()`로 그 파일을 업로드합니다. 의도적입니다: 게이트에서 실패하는
빌드라도 findings는 기록으로 남아야지, 버려져서는 안 됩니다. 실패한 스텝 뒤에 업로드하거나
`--fail-on`이 업로드 전에 중단시키면, Security 탭이 존재하는 이유인 그 기록을 잃습니다.

```yaml
- name: Scan
  id: scan
  run: |
    set +e
    assay scan "$IMAGE" --output sarif --fail-on high > assay.sarif
    echo "exit_code=$?" >> "$GITHUB_OUTPUT"
- name: Upload SARIF
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: assay.sarif, category: assay }
- name: Fail on findings
  run: exit ${{ steps.scan.outputs.exit_code }}
```

코드 스캐닝 업로드를 가능하게 하는 것은 `security-events: write` 권한입니다.

## 데이터베이스

`assay db update`는 발행된 데이터베이스를 `ghcr.io/kun9497/assay-db`에서 당겨옵니다 — OCI
아티팩트라 시간이 아니라 수 초이고, 2026-08-28부터 **public**이라 로그인도 packages 권한도
필요 없습니다. 파이프라인이 ghcr.io 자체에 닿을 수 없으면 대신 `assay db build`를
돌리세요 — 상류 소스에서 데이터베이스를 직접 빌드하며 외부 아티팩트가 필요 없습니다
(시간이 드는 대신).

데이터베이스는 스캔과 직교합니다: 잡마다 한 번 갱신(또는 캐시)하면, 이후 모든 `assay
scan`은 읽기만 합니다. SBOM이나 로컬 tarball 스캔은 네트워크 호출을 전혀 하지 않습니다.

## 받아들인 finding waive하기

어떤 finding은 진짜이지만 당신의 프로젝트와는 무관합니다 — CVE가 쓰지 않는
코드 경로에 있거나, 완화 조치를 했거나, 위험을 감수하기로 했을 수 있습니다.
그런 것들은 저장소의 `.assay.yaml`에 넣으세요(기본으로 스캔됨;
`--config <path>`로 다른 파일을 지정할 수 있습니다):

```yaml
ignore:
  - vulnerability: CVE-2024-58251   # CVE나 advisory id (alias도 셈)
    package: busybox                # 선택: 이 패키지에만 적용
    reason: not reachable in our build path   # 필수 — 이유 없는 waiver는 거부됨
    expires: 2026-12-31             # 선택: 이 날짜 이후로는 규칙이 waive를 멈추고 경고함
```

규칙은 이름 붙인 필드 '전부'가 매칭될 때만 finding을 waive합니다(`reason`은
필수입니다; 매칭 필드가 없는 규칙은 모든 것을 waive하게 되므로 거부됩니다).
waive된 finding은 **보여지지, 결코 숨겨지지 않습니다**: 리포트가 그것들을
세고("N suppressed"), 각각을 이유와 함께 이름 붙이며, `--fail-on`을 걸지
않습니다 — 하지만 출력에는 남습니다(SARIF는 그것들을 표준 `suppressions`로
표시하고, GitHub는 이를 기각된 것으로 보여줍니다). 만료된 규칙은 waive를
멈추고 경고하므로, waiver는 눈에 띄지 않게 자신의 정당화보다 오래 살 수
없습니다.

waiver가 당신이 아니라 소프트웨어의 '생산자'로부터 온 것이라면, 그것을
받아 적는 대신 그들의 OpenVEX 문서를 넘기세요: `--vex <path>`(반복 가능)가
그 문서의 `not_affected`와 `fixed` statement를 같은 방식으로 적용합니다 —
억제된 finding은 세어지고, statement 자신의 justification과 author를
이유로 삼아 표시되며, 이유가 없는 statement는 받아들여지는 대신 경고와
함께 건너뛰어집니다. `affected`와 `under_investigation` statement는
결코 아무것도 억제하지 않습니다.

```sh
assay scan my-image.tar --vex vendor.openvex.json --fail-on high
```

## `--output json | jq`로 충분하지 않은 이유

충분합니다 — JSON은 각 소스의 등급, 소스별 수정 버전, skip 개수를 모두 담고, 스트림 규율
덕에 `jq`용으로 깨끗합니다. SARIF는 findings를 GitHub Security 탭에 리뷰어가 인라인으로
보는 주석으로 올려주는 추가 단계일 뿐입니다. 플랫폼이 읽는 쪽을 쓰세요 — 둘 다 같은
스캔에서 나옵니다.
