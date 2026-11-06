#!/usr/bin/env bash
# Starts SonarQube (if needed), creates a token, runs the scanner, and dumps issues to reports/.
# Usage: ./run_sonar.sh            (uses admin/admin on first run, then $SONAR_ADMIN_PASS)
set -euo pipefail
cd "$(dirname "$0")"
HOST=http://localhost:9000
PROJECT=buggy-python-app
ADMIN_PASS=${SONAR_ADMIN_PASS:-Admin123!Admin}

docker compose up -d sonarqube
echo "Waiting for SonarQube to be UP..."
until curl -s "$HOST/api/system/status" | grep -q '"status":"UP"'; do sleep 5; done

# First run: change default admin password (SonarQube forces this).
curl -s -u admin:admin -X POST "$HOST/api/users/change_password" \
  -d "login=admin&previousPassword=admin&password=$ADMIN_PASS" >/dev/null || true

TOKEN=$(curl -s -u "admin:$ADMIN_PASS" -X POST "$HOST/api/user_tokens/generate" \
  -d "name=scan-$(date +%s)&type=GLOBAL_ANALYSIS_TOKEN" | sed -E 's/.*"token":"([^"]+)".*/\1/')

docker run --rm --network host -v "$PWD:/usr/src" \
  -e SONAR_HOST_URL="$HOST" -e SONAR_TOKEN="$TOKEN" \
  sonarsource/sonar-scanner-cli:latest

echo "Waiting for background analysis task..."
sleep 10
until curl -s -u "admin:$ADMIN_PASS" "$HOST/api/ce/component?component=$PROJECT" \
      | grep -q '"queue":\[\]'; do sleep 3; done

mkdir -p reports
curl -s -u "admin:$ADMIN_PASS" "$HOST/api/issues/search?componentKeys=$PROJECT&ps=500" > reports/sonar-issues.json
curl -s -u "admin:$ADMIN_PASS" "$HOST/api/hotspots/search?project=$PROJECT&ps=500" > reports/sonar-hotspots.json
curl -s -u "admin:$ADMIN_PASS" "$HOST/api/measures/component?component=$PROJECT&metricKeys=bugs,vulnerabilities,code_smells,security_hotspots,coverage,duplicated_lines_density,ncloc,sqale_rating,reliability_rating,security_rating,cognitive_complexity" > reports/sonar-measures.json
curl -s -u "admin:$ADMIN_PASS" "$HOST/api/qualitygates/project_status?projectKey=$PROJECT" > reports/sonar-qualitygate.json
echo "Dashboard: $HOST/dashboard?id=$PROJECT  (login admin / $ADMIN_PASS)"
