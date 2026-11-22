# CyberDesk – CI/CD i bezpieczeństwo w CI/CD (L5 i L6)

## Jak to działa

```
 commit + PR ──► CI (.github/workflows/ci.yml)  ── każdy job to bramka ──┐
                 ├─ Lint & Test         ruff + 28 testów (pytest)        │ czerwone =
                 ├─ SAST & dependencies Bandit + pip-audit (CVE)         │ PR nie może
                 ├─ Secret scan         Gitleaks                         │ trafić do main
                 ├─ IaC scan            cfn-lint + Checkov               │
                 ├─ Build & scan image  docker build + Trivy             │
                 └─ DAST (OWASP ZAP)    skan działającej aplikacji ──────┘
                                    │ zielone
 merge do main ──► CI na main ──► Deploy (.github/workflows/deploy.yml)
                                    │
                         ⏸ RĘCZNE ZATWIERDZENIE (GitHub Environment "production")
                                    │
                 1. CloudFormation  ─ infrastruktura z cyberdesk-template.yaml (bez zmian = no-op)
                 2. ECR             ─ obraz z tagiem = SHA commita (niezmienialny)
                 3. SSM Parameter   ─ /cyberdesk/image-tag (nowe instancje z autoskalowania startują tę wersję)
                 4. SSM Run Command ─ rolling deploy: po jednej instancji, błąd = stop
                 5. Smoke test      ─ https://app.cyberdesk.com.pl/health
```

- **Testy blokują wdrożenie:** deploy uruchamia się wyłącznie po zielonym CI na `main`.
- **Wdrożenie nie jest automatyczne:** job deployu czeka na zatwierdzenie osoby z listy reviewerów.
- **CI/CD dla infrastruktury:** szablon jest skanowany w CI (cfn-lint, Checkov) i wdrażany przez pipeline (CloudFormation).

## Jednorazowy setup (przed pierwszym merge)

> Kolejność ma znaczenie. Szczególnie krok 3: jeśli Environment `production` nie będzie miał reviewerów,
> GitHub utworzy go automatycznie **bez bramki** i deploy przejdzie bez zatwierdzenia.

### 1. AWS – stack CI/CD (admin konta, raz, ~1 min)
1. CloudFormation → **Create stack** → *With new resources* → *Upload a template file* → `infra/cyberdesk-cicd.yaml`.
2. Stack name: `cyberdesk-cicd`. Parametry zostaw domyślne.
   - Jeśli dostaniesz błąd, że provider `token.actions.githubusercontent.com` już istnieje: IAM → *Identity providers* → skopiuj jego ARN do parametru `ExistingOIDCProviderArn` i spróbuj ponownie.
3. Na ostatniej stronie zaznacz **„I acknowledge that AWS CloudFormation might create IAM resources with custom names”** → Submit.
4. Po `CREATE_COMPLETE` zakładka **Outputs**: skopiuj `AwsDeployRoleArn` i `CfnExecutionRoleArn`.
5. Route 53 → *Hosted zones* → `cyberdesk.com.pl` → skopiuj **Hosted zone ID** (zaczyna się od `Z`).

Upewnij się też, że **nie istnieje żaden inny stack** z tą samą domeną (`app.cyberdesk.com.pl`) ani osierocona instancja RDS `cyberdesk-rdsdatabase-*`.
Stacku aplikacji `CyberDesk` **nie twórz ręcznie** – zrobi to pipeline.

### 2. GitHub – zmienne repo (admin repo)
Settings → Secrets and variables → Actions → zakładka **Variables** → *New repository variable*:

| Nazwa | Wartość | Wymagana |
|---|---|---|
| `AWS_DEPLOY_ROLE_ARN` | output `AwsDeployRoleArn` | tak |
| `CFN_EXECUTION_ROLE_ARN` | output `CfnExecutionRoleArn` | tak |
| `HOSTED_ZONE_ID` | Hosted zone ID z Route 53 | tak |
| `AWS_REGION` | `eu-north-1` (domyślnie) | nie |
| `APP_DOMAIN` | `app.cyberdesk.com.pl` (domyślnie) | nie |
| `DEMO_MODE` | `1` = konta demo (domyślnie), `0` = bez | nie |
| `DB_MULTI_AZ` | `true` (domyślnie), `false` = taniej na testy | nie |

To są **zmienne, nie sekrety** – ARN-y ról nie są tajne. Żadne hasło ani klucz AWS nie trafia do GitHuba.

### 3. GitHub – Environment z ręczną bramką (admin repo)
Settings → **Environments** → *New environment* → nazwa dokładnie `production`:
- **Required reviewers:** dodaj osoby, które mogą zatwierdzać wdrożenia (np. Szymon i Kusio).
- **Deployment branches and tags:** *Selected branches and tags* → dodaj regułę `main`.

### 4. GitHub – ochrona gałęzi `main` (admin repo)
Settings → **Branches** (albo *Rules → Rulesets*) → reguła dla `main`:
- *Require a pull request before merging*,
- *Require status checks to pass* → wybierz: `Lint & Test`, `SAST & dependencies`, `Secret scan`, `IaC scan`, `Build & scan image`, `DAST (OWASP ZAP)`
  (pojawią się na liście po pierwszym przebiegu CI na PR).

Jeśli właścicielem repo jest **organizacja** (nie konto osobiste), Gitleaks wymaga darmowej licencji: sekret `GITLEAKS_LICENSE` (gitleaks.io).

## Codzienna praca
1. Gałąź → zmiany → commit → PR do `main`. CI uruchamia się samo.
2. Wszystko zielone → merge.
3. Actions → workflow **Deploy** → *Review deployments* → **Approve**.
4. Po kilku minutach nowa wersja działa pod `https://app.cyberdesk.com.pl`.

Pierwsze wdrożenie tworzy całą infrastrukturę i trwa **ok. 25–35 min** (najdłużej RDS Multi-AZ). Kolejne: kilka minut.
Ręczny redeploy aktualnego `main`: Actions → Deploy → *Run workflow*.

## Mapowanie na wymagania

### L5 – proces CI/CD
| Wymaganie | Realizacja |
|---|---|
| Testy po zmianie w repo | `ci.yml` na każdy PR i push |
| Testy pozwalają dodać kod do mastera | branch protection: wymagane checki CI |
| Nieudane testy zatrzymują wdrożenie | `deploy.yml` startuje tylko po `conclusion == success` CI na `main` |
| Wdrożenie nie jest automatyczne | GitHub Environment `production` z required reviewers |
| Sposób deploymentu | obraz w ECR (tag = SHA) → SSM Run Command, rolling po 1 instancji, smoke test |
| *CI/CD dla infrastruktury | cfn-lint + Checkov w CI; `aws cloudformation deploy` w pipeline (IaC) |
| Zabezpieczenia master/prod | branch protection + bramka Environment + rola AWS dostępna tylko w `production` |

### L6 – bezpieczeństwo w CI/CD
| Element | Narzędzie / mechanizm |
|---|---|
| SAST | Bandit (fałszywe alarmy B608 przeanalizowane i opisane w kodzie) |
| SCA (zależności) | pip-audit – wykrył CVE we Flask 3.0.0 → podbity do 3.1.3 |
| Sekrety w repo | Gitleaks; domyślne hasło bazy usunięte z szablonu (teraz generowane w Secrets Manager) |
| Skan obrazu | Trivy w CI + ECR scan-on-push |
| Skan IaC | cfn-lint + Checkov; zaakceptowane ryzyka opisane w `Metadata` szablonów |
| DAST | OWASP ZAP baseline na działającej aplikacji (docker compose + PostgreSQL) |
| Klucze / tożsamość | OIDC GitHub → AWS: brak długożyjących kluczy; rola tylko dla repo + Environment `production` |
| Least privilege pipeline | rola GitHub może tylko: push do 1 repo ECR, zmiany 1 stacku przez rolę CloudFormation, komendy SSM na instancje z tagiem `Project=CyberDesk` |
| Sekrety aplikacji | AWS Secrets Manager (generowane, nigdzie nie zapisane w kodzie) |
| Łańcuch dostaw | akcje przypięte do SHA commitów, narzędzia do wersji (`requirements-ci.txt`) |
| Hardening runtime | IMDSv2, szyfrowane EBS i RDS, TLS 1.2+ na ALB, HTTP→HTTPS, kontener read-only bez capabilities, aplikacja jako `cyberdesk_app` bez prawa DDL |

## Zmiany w aplikacji wynikające z wdrożenia na AWS
- **Bootstrap bazy (`scripts/bootstrap_db.py`)** – na RDS nie działa `db-init.sh`, więc schemat i ograniczony użytkownik `cyberdesk_app` są tworzone idempotentnie przy starcie kontenera (z blokadą `pg_advisory_lock`, bo kilka instancji startuje naraz). Sprawdzone na prawdziwym PostgreSQL 16: 3 równoległe starty, aplikacja działa jako `cyberdesk_app`, który nie może usunąć tabeli.
- **ProxyFix (`TRUST_PROXY=1`)** – za ALB każdy użytkownik miałby adres IP load balancera: limit prób logowania blokowałby **wszystkich naraz**, a HSTS nie byłby wysyłany. Pokryte testami w `tests/test_proxy.py`.
- **Flask 3.0.0 → 3.1.3** – znana podatność wykryta przez pip-audit.

## Koszty i sprzątanie
Działający stack (NAT Gateway, ALB, 2× EC2, RDS Multi-AZ) kosztuje kilka USD dziennie z kredytów.
Po prezentacji: CloudFormation → stack `CyberDesk` → **Delete** (baza usuwana bez snapshotu).
Stack `cyberdesk-cicd` może zostać – nie generuje kosztów poza miejscem na obrazy w ECR.

## Świadomie zaakceptowane ryzyka
- `DEMO_MODE=1` tworzy konta demonstracyjne z hasłami pokazanymi na stronie logowania – wygodne na prezentację, ale na publicznej domenie to ryzyko. Po prezentacji ustawcie zmienną `DEMO_MODE=0`.
- Brak WAF, access logów ALB, VPC Flow Logs i Enhanced Monitoring RDS – koszt; każdy wyjątek opisany przy zasobie (`Metadata: checkov`).
- Rola wykonawcza CloudFormation ma `AdministratorAccess`, ale może jej użyć wyłącznie usługa CloudFormation, a GitHub może ją przekazać tylko do zmian stacku `CyberDesk`.
- W historii gita zostały stare sekrety (klucz Flaska z pierwszej wersji aplikacji i domyślne hasło bazy z szablonu). Nie są już używane: produkcyjne hasła i klucz pochodzą z Secrets Manager. Historii nie przepisujemy, bo zmieniłoby to SHA wszystkich commitów we wspólnym repo.
