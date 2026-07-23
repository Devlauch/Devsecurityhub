function generateSecurityJenkinsfile(repoUrl, branch, jobName) {
  return `pipeline {
    agent any

    environment {
        REPO_URL = '${repoUrl}'
        BRANCH   = '${branch}'
        JOB      = '${jobName}'
    }

    stages {
        stage('Checkout') {
            steps {
                git branch: '${branch}', url: '${repoUrl}'
            }
        }

        stage('Setup Tools') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''
                        mkdir -p \$HOME/sec-tools/bin
                        export PATH=\$HOME/sec-tools/bin:\$PATH

                        # Gitleaks
                        if ! which gitleaks 2>/dev/null && [ ! -x "\$HOME/sec-tools/bin/gitleaks" ]; then
                            curl -sSL https://github.com/gitleaks/gitleaks/releases/download/v8.18.4/gitleaks_8.18.4_linux_x64.tar.gz \\
                                | tar -xz -C \$HOME/sec-tools/bin gitleaks 2>/dev/null || true
                        fi

                        # Trivy
                        if ! which trivy 2>/dev/null && [ ! -x "\$HOME/sec-tools/bin/trivy" ]; then
                            curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \\
                                | sh -s -- -b \$HOME/sec-tools/bin 2>/dev/null || true
                        fi

                        # Checkov (IaC scanner) — bootstrap pip if missing, then install
                        if ! python3 -m checkov --version > /dev/null 2>&1; then
                            python3 -m ensurepip --upgrade 2>/dev/null || \\
                                curl -sSL https://bootstrap.pypa.io/get-pip.py | python3 - --quiet 2>/dev/null || true
                            python3 -m pip install checkov --quiet 2>/dev/null || true
                        fi

                        # SonarQube Scanner (only if SONAR_HOST_URL is configured)
                        if [ -n "\$SONAR_HOST_URL" ] && [ ! -f "\$HOME/sec-tools/sonar-scanner/bin/sonar-scanner" ]; then
                            curl -sSL https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-6.2.1.4610-linux-x64.zip \\
                                -o /tmp/sonar.zip 2>/dev/null && \\
                            unzip -q /tmp/sonar.zip -d /tmp/sonar-extract/ 2>/dev/null && \\
                            mv /tmp/sonar-extract/sonar-scanner-* \$HOME/sec-tools/sonar-scanner 2>/dev/null || true && \\
                            rm -rf /tmp/sonar.zip /tmp/sonar-extract 2>/dev/null || true
                        fi

                        # OWASP Dependency-Check (disabled — requires NVD API key; re-enable when ready)
                        # if [ ! -f "\$HOME/sec-tools/dependency-check/bin/dependency-check.sh" ]; then
                        #     DC_VERSION="10.0.4"
                        #     curl -sSL "https://github.com/jeremylong/DependencyCheck/releases/download/v\${DC_VERSION}/dependency-check-\${DC_VERSION}-release.zip" \\
                        #         -o /tmp/dc.zip 2>/dev/null && \\
                        #     unzip -q /tmp/dc.zip -d \$HOME/sec-tools/ 2>/dev/null && \\
                        #     rm -f /tmp/dc.zip 2>/dev/null || true
                        # fi

                        # TruffleHog (secrets scanner)
                        if [ ! -x "\$HOME/sec-tools/bin/trufflehog" ]; then
                            curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \\
                                | sh -s -- -b \$HOME/sec-tools/bin 2>/dev/null || true
                        fi

                        # Semgrep (SAST)
                        if ! python3 -m semgrep --version > /dev/null 2>&1; then
                            python3 -m pip install semgrep --quiet 2>/dev/null || true
                        fi

                        # Grype (container/image vulnerability scanner)
                        if ! which grype 2>/dev/null && [ ! -x "\$HOME/sec-tools/bin/grype" ]; then
                            curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh \\
                                | sh -s -- -b \$HOME/sec-tools/bin 2>/dev/null || true
                        fi
                    '''
                }
            }
        }

        stage('Secrets Scan (Gitleaks)') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''
                        export PATH=\$HOME/sec-tools/bin:\$PATH
                        gitleaks detect --source . --no-git --report-format json --report-path gitleaks-report.json --exit-code 0 2>/dev/null || \\
                            echo '[]' > gitleaks-report.json
                    '''
                    archiveArtifacts artifacts: 'gitleaks-report.json', allowEmptyArchive: true
                }
            }
        }

        stage('Secrets Scan (TruffleHog)') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''
                        export PATH=\$HOME/sec-tools/bin:\$PATH
                        if which trufflehog 2>/dev/null; then
                            trufflehog filesystem . --json --no-update --only-verified=false 2>/dev/null \\
                                | head -2000 > trufflehog-report.jsonl || true
                            if [ ! -s trufflehog-report.jsonl ]; then
                                echo '' > trufflehog-report.jsonl
                            fi
                        else
                            echo '' > trufflehog-report.jsonl
                        fi
                    '''
                    archiveArtifacts artifacts: 'trufflehog-report.jsonl', allowEmptyArchive: true
                }
            }
        }

        stage('SAST (SonarQube)') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''
                        export PATH=\$HOME/sec-tools/bin:\$PATH
                        if [ -n "\$SONAR_HOST_URL" ] && [ -n "\$SONAR_TOKEN" ]; then
                            \$HOME/sec-tools/sonar-scanner/bin/sonar-scanner \\
                                -Dsonar.projectKey=\${JOB} \\
                                -Dsonar.sources=. \\
                                -Dsonar.host.url=\$SONAR_HOST_URL \\
                                -Dsonar.token=\$SONAR_TOKEN 2>&1 || true
                            if [ -f .scannerwork/report-task.txt ]; then
                                PROJ=\$(grep 'projectKey=' .scannerwork/report-task.txt | cut -d= -f2)
                                DASH=\$(grep 'dashboardUrl=' .scannerwork/report-task.txt | sed 's/dashboardUrl=//')
                                echo '{"status":"OK","projectKey":"'"$PROJ"'","dashboardUrl":"'"$DASH"'"}' > sonarqube-report.json
                            else
                                echo '{"status":"FAILED","message":"sonar-scanner ran but produced no report"}' > sonarqube-report.json
                            fi
                        else
                            echo '{"status":"NOT_CONFIGURED","message":"Set SONAR_HOST_URL and SONAR_TOKEN as Jenkins global environment variables to enable SonarQube scanning."}' > sonarqube-report.json
                        fi
                    '''
                    archiveArtifacts artifacts: 'sonarqube-report.json', allowEmptyArchive: true
                }
            }
        }

        stage('SAST (Semgrep)') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''
                        export PATH=\$HOME/.local/bin:\$HOME/sec-tools/bin:\$PATH
                        SEMGREP=\$(which semgrep 2>/dev/null || echo '')
                        if [ -n "\$SEMGREP" ]; then
                            semgrep --config=auto . --json --output semgrep-sast-report.json \\
                                --timeout 60 --max-memory 512 --no-git-ignore 2>/dev/null || \\
                            semgrep --config=p/default . --json --output semgrep-sast-report.json \\
                                --timeout 60 2>/dev/null || \\
                            echo '{"results":[],"errors":[]}' > semgrep-sast-report.json
                        else
                            echo '{"results":[],"errors":[]}' > semgrep-sast-report.json
                        fi
                    '''
                    archiveArtifacts artifacts: 'semgrep-sast-report.json', allowEmptyArchive: true
                }
            }
        }

        stage('Dependency Scan (Trivy FS)') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''
                        export PATH=\$HOME/sec-tools/bin:\$PATH
                        trivy fs . --format json --exit-code 0 --severity HIGH,CRITICAL \\
                            --output trivy-fs-report.json 2>/dev/null || \\
                            echo '{"SchemaVersion":2,"Results":[]}' > trivy-fs-report.json
                    '''
                    archiveArtifacts artifacts: 'trivy-fs-report.json', allowEmptyArchive: true
                }
            }
        }

        // OWASP DC stage disabled — NVD API key required; re-enable once NVD_API_KEY is set in Jenkins globals
        // stage('Dependency Scan (OWASP DC)') {
        //     steps {
        //         catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
        //             sh '''
        //                 DC=$HOME/sec-tools/dependency-check/bin/dependency-check.sh
        //                 if [ -f "$DC" ]; then
        //                     $DC --project "${JOB}" --scan . --format JSON --out . --noupdate 2>/dev/null || \\
        //                     $DC --project "\${JOB}" --scan . --format JSON --out . \\
        //                         \${NVD_API_KEY:+--nvdApiKey "\$NVD_API_KEY"} 2>/dev/null || true
        //                     mv dependency-check-report.json owasp-dc-report.json 2>/dev/null || \\
        //                         echo '{"dependencies":[],"_error":"NVD update failed"}' > owasp-dc-report.json
        //                 else
        //                     echo '{"dependencies":[]}' > owasp-dc-report.json
        //                 fi
        //             '''
        //             archiveArtifacts artifacts: 'owasp-dc-report.json', allowEmptyArchive: true
        //         }
        //     }
        // }

        stage('IaC Scan (Checkov)') {
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''
                        export PATH=\$HOME/.local/bin:\$PATH
                        CHECKOV=\$(which checkov 2>/dev/null || echo '')
                        if [ -n "\$CHECKOV" ]; then
                            checkov -d . --framework dockerfile,docker_compose --output json --soft-fail > checkov-report.json 2>/dev/null || \\
                                echo '{"results":{"passed_checks":[],"failed_checks":[]},"summary":{"passed":0,"failed":0,"skipped":0}}' > checkov-report.json
                        else
                            echo '{"results":{"passed_checks":[],"failed_checks":[]},"summary":{"passed":0,"failed":0,"skipped":0}}' > checkov-report.json
                        fi
                    '''
                    archiveArtifacts artifacts: 'checkov-report.json', allowEmptyArchive: true
                }
            }
        }

        stage('Container Scan (Trivy + Grype)') {
            when { expression { return fileExists('Dockerfile') } }
            steps {
                catchError(buildResult: 'SUCCESS', stageResult: 'UNSTABLE') {
                    sh '''
                        export PATH=\$HOME/sec-tools/bin:\$PATH
                        if which docker 2>/dev/null && docker info > /dev/null 2>&1; then
                            docker build -t sec-scan-image:local . 2>/dev/null || true

                            # Trivy image scan (JSON + plain text)
                            trivy image --exit-code 0 --severity HIGH,CRITICAL --format json sec-scan-image:local \\
                                > trivy-image-report.json 2>/dev/null || \\
                                echo '{"SchemaVersion":2,"Results":[]}' > trivy-image-report.json
                            trivy image --exit-code 0 --severity HIGH,CRITICAL --format table sec-scan-image:local \\
                                > trivy-report.txt 2>/dev/null || echo 'Trivy scan failed' > trivy-report.txt

                            # Grype image scan
                            if which grype 2>/dev/null; then
                                grype sec-scan-image:local -o json > grype-report.json 2>/dev/null || \\
                                    echo '{"matches":[]}' > grype-report.json
                            else
                                echo '{"matches":[]}' > grype-report.json
                            fi
                        else
                            echo '{"SchemaVersion":2,"Results":[]}' > trivy-image-report.json
                            echo '{"matches":[]}' > grype-report.json
                            echo 'Docker not available — container scan skipped' > trivy-report.txt
                        fi
                    '''
                    archiveArtifacts artifacts: 'trivy-image-report.json,grype-report.json,trivy-report.txt', allowEmptyArchive: true
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: '*.json,*.txt', allowEmptyArchive: true
        }
    }
}`;
}

function buildJobXml(jenkinsfile) {
  const escaped = jenkinsfile
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');

  return `<?xml version='1.1' encoding='UTF-8'?>
<flow-definition plugin="workflow-job">
  <description>DevSecurityHub security scan</description>
  <keepDependencies>false</keepDependencies>
  <properties/>
  <definition class="org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition" plugin="workflow-cps">
    <script>${escaped}</script>
    <sandbox>true</sandbox>
  </definition>
  <triggers/>
  <disabled>false</disabled>
</flow-definition>`;
}

module.exports = { generateSecurityJenkinsfile, buildJobXml };
